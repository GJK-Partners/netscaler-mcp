<#
.SYNOPSIS
    De lokale-padregel aan de PowerShell-kant: Open-GjkLokaalBestand.
.DESCRIPTION
    Windows PowerShell 5.1, ASCII-only. Dot-source dit bestand (de faserunner
    doet dat zelf, op naam uit zijn eigen map; het valt dus onder de scriptpin
    van die map).

    Een padcontrole gevolgd door een losse open op naam is niet veilig: een
    voorouder die tussen de controle en de open een junction wordt, wordt door
    de open gevolgd voordat er een handle is. Daarom opent deze functie, net als
    nsmcp.localpath aan de Python-kant, ELK onderdeel zelf, relatief aan een
    handle die zij vasthoudt, en volgt zij nooit een koppeling door een open:

      1. spelling, zonder iets te openen (UNC en apparaatpad, dubbele punt
         na de schijfletter, onderdeel dat op punt of spatie eindigt; strikt
         absoluut X:\... of \\?\Volume{GUID}\..., geen leeg, . of .. onderdeel);
      2. volume, zonder het pad te openen: GetDriveTypeW moet DRIVE_FIXED zijn
         en QueryDosDeviceW precies een \Device\HarddiskVolumeN geven;
      3. de volumewortel geopend op dat apparaatdoel (NtCreateFile), getoetst
         met GetFileType en NtQueryVolumeInformationFile;
      4. elk volgend onderdeel met NtCreateFile relatief aan de vastgehouden
         ouder, met FILE_OPEN_REPARSE_POINT en zonder typevlag; mappen met
         alleen traverseerrecht en zonder FILE_SHARE_DELETE vastgehouden tot
         Close-GjkLokaalBestand;
      5. na elke open EERST de tag (NtQueryInformationFile,
         FileAttributeTagInformation), dan pas het type. Binnen de wortel, de
         wortel zelf inbegrepen, is elk herparseerpunt een weigering; boven de
         wortel wordt alleen een symlink of mount point gevolgd, waarvan de
         gegevens van de koppeling zelf gelezen worden
         (DeviceIoControl FSCTL_GET_REPARSE_POINT) en het doel eerst stap 1
         en 2 doorloopt;
      6. het blad gelezen op zijn eigen handle: een FileStream op de
         vastgehouden bladhandle (ReadFile), geen tweede open op naam;
      7. containment is structureel: de wortel wordt op haar eigen tekst
         gewandeld (het pad moet ordinaal exact met die tekst beginnen, anders
         buiten_wortel) en alles eronder relatief aan de wortelhandle geopend.

    Deelmodus per bestandsklasse: ledger en runnerlog FILE_SHARE_READ |
    FILE_SHARE_WRITE (een andere schrijver mag aanvullen terwijl gelezen
    wordt); bundel, sidecar en pakket alleen FILE_SHARE_READ (de bytes blijven
    vast zolang het blad vastgehouden is). Alleen lezen: geen PowerShell-route
    schrijft via deze functie, en een schrijfroute die niets gebruikt wordt
    niet aangeboden.

    Een weigering is een [GjkLokaalPad.PadGeweigerd] met een Soort uit dezelfde
    vaste verzameling als nsmcp.localpath.SOORTEN en, als boodschap, dezelfde
    vaste zin zonder pad (REASONS). Het pad en de NTSTATUS gaan alleen naar
    stderr, en alleen met NSMCP_DEBUG.

    Naad voor de tests ([GjkLokaalPad.Naad]): telt elke native aanroep, noteert
    elke open met zijn ouderhandle, voert tussen twee onderdelen een wissel uit
    (Tussen) en kan stationstype, apparaatdoel, een status of een tag
    vervangen. Geen parameter van een script bereikt die naad.
.NOTES
    GJK Partners. ASCII-only, Windows PowerShell 5.1.
#>
Set-StrictMode -Version Latest

if (-not ('GjkLokaalPad.Wandeling' -as [type])) {
    Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace GjkLokaalPad
{
    public class PadGeweigerd : IOException
    {
        private readonly string soort;
        public string Detail;
        public string Pad;
        public long Status = -1;
        public bool Gevolgd;

        public PadGeweigerd(string soort, string pad, string detail)
            : base(Wandeling.Reden(Wandeling.BekendeSoort(soort)))
        {
            string bekend = Wandeling.BekendeSoort(soort);
            this.Detail = bekend == soort ? (detail ?? "") : "onbekende soort " + soort;
            this.soort = bekend;
            this.Pad = pad;
        }

        public string Soort { get { return soort; } }
        public string Reden { get { return Wandeling.Reden(soort); } }
    }

    public class OpenRegel
    {
        public long Ouder;
        public string Naam;
        public uint Status;
        public long Handle;
        public uint Toegang;
        public uint Deling;
        public uint Dispositie;
        public uint Opties;
    }

    public static class Naad
    {
        public static bool Opnemen;
        public static readonly Dictionary<string, int> Aanroepen = new Dictionary<string, int>(StringComparer.Ordinal);
        public static readonly List<OpenRegel> Opens = new List<OpenRegel>();
        public static readonly List<long> Sluitingen = new List<long>();
        public static readonly List<string> Gebeurtenissen = new List<string>();
        public static Action<int, string> Tussen;
        public static Func<string, uint> Stationstype;
        public static Func<string, string[]> Apparaatdoel;
        public static Func<string, uint> Status;
        public static readonly Dictionary<string, uint> Tag = new Dictionary<string, uint>(StringComparer.Ordinal);

        public static void Wis()
        {
            Opnemen = false;
            Aanroepen.Clear();
            Opens.Clear();
            Sluitingen.Clear();
            Gebeurtenissen.Clear();
            Tussen = null;
            Stationstype = null;
            Apparaatdoel = null;
            Status = null;
            Tag.Clear();
        }

        public static int Teller(string naam)
        {
            int n;
            return Aanroepen.TryGetValue(naam, out n) ? n : 0;
        }

        internal static void Tel(string naam)
        {
            Aanroepen[naam] = Teller(naam) + 1;
        }

        internal static void NoteerOpen(IntPtr ouder, string naam, uint status, IntPtr handle, uint toegang, uint deling, uint dispositie, uint opties)
        {
            if (!Opnemen) { return; }
            OpenRegel regel = new OpenRegel();
            regel.Ouder = ouder.ToInt64();
            regel.Naam = naam;
            regel.Status = status;
            regel.Handle = handle.ToInt64();
            regel.Toegang = toegang;
            regel.Deling = deling;
            regel.Dispositie = dispositie;
            regel.Opties = opties;
            Opens.Add(regel);
            Gebeurtenissen.Add("open:" + (Opens.Count - 1));
        }

        internal static void NoteerSluiten(IntPtr handle)
        {
            if (!Opnemen) { return; }
            Sluitingen.Add(handle.ToInt64());
            Gebeurtenissen.Add("close:" + handle.ToInt64());
        }
    }

    internal static class Inheems
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct IO_STATUS_BLOCK
        {
            public IntPtr Status;
            public IntPtr Information;
        }

        [DllImport("ntdll.dll")]
        private static extern int NtCreateFile(out IntPtr handle, uint access, ref OBJECT_ATTRIBUTES attributes, out IO_STATUS_BLOCK ioStatus, IntPtr allocationSize, uint fileAttributes, uint share, uint disposition, uint options, IntPtr eaBuffer, uint eaLength);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationFile(IntPtr handle, out IO_STATUS_BLOCK ioStatus, IntPtr information, uint length, int informationClass);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryVolumeInformationFile(IntPtr handle, out IO_STATUS_BLOCK ioStatus, IntPtr information, uint length, int informationClass);

        [DllImport("ntdll.dll")]
        private static extern int NtClose(IntPtr handle);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern uint GetDriveTypeW(string root);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint QueryDosDeviceW(string name, [Out] char[] buffer, uint max);

        [DllImport("kernel32.dll")]
        private static extern uint GetFileType(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(IntPtr handle, uint code, IntPtr inBuffer, uint inSize, [Out] byte[] outBuffer, uint outSize, out uint returned, IntPtr overlapped);

        private const uint OBJ_CASE_INSENSITIVE = 0x40;
        private const uint FSCTL_GET_REPARSE_POINT = 0x000900A8;

        internal static uint Maak(IntPtr ouder, string naam, uint toegang, uint deling, uint dispositie, uint opties, out IntPtr handle)
        {
            Naad.Tel("NtCreateFile");
            handle = IntPtr.Zero;
            uint status = 0;
            if (Naad.Status != null) { status = Naad.Status(naam); }
            if (status == 0)
            {
                IntPtr buffer = Marshal.StringToHGlobalUni(naam);
                IntPtr tekst = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
                try
                {
                    UNICODE_STRING us = new UNICODE_STRING();
                    us.Length = (ushort)(naam.Length * 2);
                    us.MaximumLength = (ushort)(naam.Length * 2 + 2);
                    us.Buffer = buffer;
                    Marshal.StructureToPtr(us, tekst, false);
                    OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
                    oa.Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
                    oa.RootDirectory = ouder;
                    oa.ObjectName = tekst;
                    oa.Attributes = OBJ_CASE_INSENSITIVE;
                    IO_STATUS_BLOCK io;
                    status = unchecked((uint)NtCreateFile(out handle, toegang, ref oa, out io, IntPtr.Zero, 0, deling, dispositie, opties, IntPtr.Zero, 0));
                }
                finally
                {
                    Marshal.FreeHGlobal(tekst);
                    Marshal.FreeHGlobal(buffer);
                }
            }
            if (status != 0) { handle = IntPtr.Zero; }
            Naad.NoteerOpen(ouder, naam, status, handle, toegang, deling, dispositie, opties);
            return status;
        }

        internal static void Sluit(IntPtr handle)
        {
            Naad.Tel("NtClose");
            Naad.NoteerSluiten(handle);
            NtClose(handle);
        }

        internal static uint Tag(IntPtr handle, string naam, out uint attributen, out uint tag)
        {
            Naad.Tel("NtQueryInformationFile");
            IntPtr info = Marshal.AllocHGlobal(8);
            try
            {
                IO_STATUS_BLOCK io;
                uint status = unchecked((uint)NtQueryInformationFile(handle, out io, info, 8, 35));
                attributen = unchecked((uint)Marshal.ReadInt32(info, 0));
                tag = unchecked((uint)Marshal.ReadInt32(info, 4));
                uint nep;
                if (status == 0 && Naad.Tag.TryGetValue(naam, out nep))
                {
                    attributen |= Wandeling.FILE_ATTRIBUTE_REPARSE_POINT;
                    tag = nep;
                }
                return status;
            }
            finally
            {
                Marshal.FreeHGlobal(info);
            }
        }

        internal static uint Standaard(IntPtr handle, out long grootte, out bool map, out uint namen)
        {
            Naad.Tel("NtQueryInformationFile");
            IntPtr info = Marshal.AllocHGlobal(24);
            try
            {
                IO_STATUS_BLOCK io;
                uint status = unchecked((uint)NtQueryInformationFile(handle, out io, info, 24, 5));
                grootte = Marshal.ReadInt64(info, 8);
                namen = unchecked((uint)Marshal.ReadInt32(info, 16));
                map = Marshal.ReadByte(info, 21) != 0;
                return status;
            }
            finally
            {
                Marshal.FreeHGlobal(info);
            }
        }

        [DllImport("ntdll.dll")]
        private static extern int NtQueryDirectoryFile(IntPtr handle, IntPtr evt, IntPtr apcRoutine, IntPtr apcContext, out IO_STATUS_BLOCK ioStatus, [Out] byte[] buffer, uint length, int informationClass, byte returnSingleEntry, IntPtr fileName, byte restartScan);

        // NtQueryDirectoryFile(FileNamesInformation = 12) op een vastgehouden
        // maphandle: alleen namen, niets geopend.
        internal static uint MapInhoud(IntPtr handle, bool opnieuw, out byte[] ruw)
        {
            Naad.Tel("NtQueryDirectoryFile");
            byte[] buffer = new byte[64 * 1024];
            IO_STATUS_BLOCK io;
            uint status = unchecked((uint)NtQueryDirectoryFile(handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out io, buffer, (uint)buffer.Length, 12, 0, IntPtr.Zero, (byte)(opnieuw ? 1 : 0)));
            if (status != 0)
            {
                ruw = new byte[0];
                return status;
            }
            int lengte = (int)io.Information.ToInt64();
            ruw = new byte[lengte];
            Array.Copy(buffer, ruw, lengte);
            return status;
        }

        internal static uint Apparaatinfo(IntPtr handle, out uint apparaatType, out uint kenmerken)
        {
            Naad.Tel("NtQueryVolumeInformationFile");
            IntPtr info = Marshal.AllocHGlobal(8);
            try
            {
                IO_STATUS_BLOCK io;
                uint status = unchecked((uint)NtQueryVolumeInformationFile(handle, out io, info, 8, 4));
                apparaatType = unchecked((uint)Marshal.ReadInt32(info, 0));
                kenmerken = unchecked((uint)Marshal.ReadInt32(info, 4));
                return status;
            }
            finally
            {
                Marshal.FreeHGlobal(info);
            }
        }

        internal static uint Stationstype(string wortel)
        {
            Naad.Tel("GetDriveTypeW");
            if (Naad.Stationstype != null) { return Naad.Stationstype(wortel); }
            return GetDriveTypeW(wortel);
        }

        internal static string[] Apparaatdoelen(string naam)
        {
            Naad.Tel("QueryDosDeviceW");
            if (Naad.Apparaatdoel != null) { return Naad.Apparaatdoel(naam); }
            char[] buffer = new char[4096];
            uint aantal = QueryDosDeviceW(naam, buffer, 4096);
            if (aantal == 0) { return null; }
            List<string> doelen = new List<string>();
            foreach (string doel in new string(buffer, 0, (int)aantal).Split('\0'))
            {
                if (doel.Length > 0) { doelen.Add(doel); }
            }
            return doelen.ToArray();
        }

        internal static uint Bestandstype(IntPtr handle)
        {
            Naad.Tel("GetFileType");
            return GetFileType(handle);
        }

        internal static byte[] Koppelingsgegevens(IntPtr handle)
        {
            Naad.Tel("DeviceIoControl");
            byte[] uit = new byte[16 * 1024];
            uint terug;
            if (!DeviceIoControl(handle, FSCTL_GET_REPARSE_POINT, IntPtr.Zero, 0, uit, (uint)uit.Length, out terug, IntPtr.Zero))
            {
                return null;
            }
            byte[] gegevens = new byte[terug];
            Array.Copy(uit, gegevens, (int)terug);
            return gegevens;
        }
    }

    internal class Volg : Exception
    {
        public readonly string Pad;
        public Volg(string pad) { Pad = pad; }
    }

    public sealed class LokaalStroom : FileStream
    {
        private readonly List<IntPtr> keten;
        private IntPtr blad;
        private bool gesloten;
        private readonly string pad;
        private readonly long grootte;

        internal LokaalStroom(IntPtr blad, List<IntPtr> keten, string pad, long grootte)
            : base(new SafeFileHandle(blad, false), FileAccess.Read, 4096, false)
        {
            this.blad = blad;
            this.keten = keten;
            this.pad = pad;
            this.grootte = grootte;
        }

        public string Pad { get { return pad; } }
        public long Grootte { get { return grootte; } }
        public bool Gesloten { get { return gesloten; } }
        public int Ketenlengte { get { return keten.Count; } }

        protected override void Dispose(bool disposing)
        {
            try
            {
                base.Dispose(disposing);
            }
            finally
            {
                if (!gesloten)
                {
                    gesloten = true;
                    try
                    {
                        if (blad != IntPtr.Zero)
                        {
                            Inheems.Sluit(blad);
                            blad = IntPtr.Zero;
                        }
                    }
                    finally
                    {
                        Wandeling.SluitAlles(keten);
                    }
                }
            }
        }
    }

    public static class Wandeling
    {
        public const int KoppelingGrens = 32;
        public const string DefectRegel = "[nsmcp-pad] DEFECT: een netwerkstatus in de lokale wandeling; deze route hoort onbereikbaar te zijn";

        public const uint FILE_READ_DATA = 0x0001;
        public const uint FILE_TRAVERSE = 0x0020;
        public const uint FILE_READ_ATTRIBUTES = 0x0080;
        public const uint SYNCHRONIZE = 0x00100000;
        public const uint FILE_SHARE_READ = 0x1;
        public const uint FILE_SHARE_WRITE = 0x2;
        public const uint FILE_SHARE_DELETE = 0x4;
        public const uint FILE_OPEN = 1;
        public const uint FILE_DIRECTORY_FILE = 0x00000001;
        public const uint FILE_SEQUENTIAL_ONLY = 0x00000004;
        public const uint FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020;
        public const uint FILE_NON_DIRECTORY_FILE = 0x00000040;
        public const uint FILE_OPEN_REPARSE_POINT = 0x00200000;
        public const uint FILE_ATTRIBUTE_DIRECTORY = 0x10;
        public const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x400;
        public const uint IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003;
        public const uint IO_REPARSE_TAG_SYMLINK = 0xA000000C;
        public const uint SYMLINK_FLAG_RELATIVE = 0x1;
        public const uint DRIVE_FIXED = 3;
        public const uint DRIVE_REMOTE = 4;
        public const uint FILE_TYPE_DISK = 1;
        public const uint FILE_DEVICE_DISK = 7;
        public const uint FILE_REMOTE_DEVICE = 0x10;

        // Een map op de weg: alleen traverseerrecht (een relatieve open vraagt
        // geen toegang op de ouderhandle); vastgehouden door de deelmodus.
        public const uint DIR_ACCESS = FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
        public const uint DIR_SHARE = FILE_SHARE_READ | FILE_SHARE_WRITE;
        public const uint LEAF_ACCESS = FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
        // Een map die zelf gevraagd wordt (opsommen): lijstrecht erbij.
        public const uint FILE_LIST_DIRECTORY = 0x0001;
        public const uint DIR_LIST_ACCESS = FILE_LIST_DIRECTORY | DIR_ACCESS;
        public const uint STATUS_NO_MORE_FILES = 0x80000006;
        public const uint STATUS_NO_SUCH_FILE = 0xC000000F;

        public const uint STATUS_OBJECT_NAME_INVALID = 0xC0000033;
        public const uint STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034;
        public const uint STATUS_OBJECT_PATH_NOT_FOUND = 0xC000003A;
        public const uint STATUS_FILE_IS_A_DIRECTORY = 0xC00000BA;
        public const uint STATUS_NOT_A_DIRECTORY = 0xC0000103;
        public const uint STATUS_REPARSE = 0x00000104;
        public const uint STATUS_STOPPED_ON_SYMLINK = 0x8000002D;
        public const uint STATUS_REPARSE_POINT_NOT_RESOLVED = 0xC0000280;
        public const uint STATUS_DIRECTORY_IS_A_REPARSE_POINT = 0xC0000281;

        private static readonly uint[] netwerkstatussen = new uint[] {
            0xC00000BE, 0xC00000BF, 0xC00000C4, 0xC00000C9, 0xC00000CC, 0xC000020C, 0xC0000236, 0xC000023C, 0xC000023D
        };

        public const string SPELLING_NETWORK_OR_DEVICE = "spelling:netwerk-of-apparaat";
        public const string SPELLING_STREAM = "spelling:dubbele-punt";
        public const string SPELLING_DOT_OR_SPACE = "spelling:punt-of-spatie";
        public const string VOLUME_REMOTE = "volume:netwerkstation";

        private static readonly string[] soorten = new string[] {
            "netwerkpad", "apparaatpad", "stroom", "netwerkstation", "koppeling", "herparseerpunt",
            "buiten_wortel", "geen_gewoon_bestand", "te_veel_koppelingen", "onleesbaar", "hardlink"
        };

        // Een vaste zin per soort, nooit een pad, nooit een status, nooit een
        // regeleinde. Byte voor byte gelijk aan nsmcp.localpath.REASONS (een
        // test houdt de twee gelijk).
        private static readonly string[] zinnen = new string[] {
            "het pad leidt naar een netwerkpad; dit product leest en schrijft alleen op een lokale schijf",
            "het pad leidt naar een apparaat of naar een station dat geen vaste lokale schijf is; dit product leest en schrijft alleen op een lokale schijf",
            "het pad noemt een alternatieve gegevensstroom (een dubbele punt in een padonderdeel); dit product leest alleen de gewone inhoud van een bestand",
            "het pad ligt op een netwerkstation; dit product leest en schrijft alleen op een lokale schijf",
            "het bestand ligt niet als gewoon lokaal bestand op de goedgekeurde plek (er zit een koppeling in het pad); dit product volgt binnen een goedgekeurde map geen koppelingen",
            "het pad gaat door een herparseerpunt dat geen gewone map of gewoon bestand is (bijvoorbeeld een cloud-plaatshouder); dit product leest of schrijft op zo'n plek niet",
            "het pad ligt buiten de goedgekeurde map",
            "op deze plek staat geen gewoon bestand of geen gewone map van de verwachte soort",
            "het pad loopt via meer dan " + 32 + " koppelingen; zo'n pad wordt niet gevolgd",
            "het pad kan niet als gewoon lokaal bestand of als gewone lokale map gelezen of vastgesteld worden",
            "het bestand heeft meer dan een naam op de schijf (hardlink); dit product leest binnen de map alleen bestanden met een naam"
        };

        private static readonly Regex lokaalApparaatStation = new Regex(@"^\\\\[?.]\\[A-Za-z]:(\\|$)");
        private static readonly Regex lokaleVolumeGuid = new Regex(@"^\\\\\?\\Volume\{[0-9A-Fa-f-]{36}\}(\\|$)");
        private static readonly Regex uncVoorvoegsel = new Regex(@"^\\\\(?:[?.]\\UNC(?:\\|$)|[^?.\\])", RegexOptions.IgnoreCase);
        private static readonly Regex harddiskVolume = new Regex(@"^\\Device\\HarddiskVolume[0-9]+\z", RegexOptions.IgnoreCase);
        private static readonly Regex striktAbsoluut = new Regex(@"^(?:[A-Za-z]:\\|\\\\[?.]\\)");
        private static readonly UnicodeEncoding striktUtf16 = new UnicodeEncoding(false, false, true);
        private const int MaxOnderdeel = 255;

        public static string[] Soorten { get { return (string[])soorten.Clone(); } }

        public static Dictionary<string, string> Redenen
        {
            get
            {
                Dictionary<string, string> kopie = new Dictionary<string, string>(StringComparer.Ordinal);
                for (int i = 0; i < soorten.Length; i++) { kopie[soorten[i]] = zinnen[i]; }
                return kopie;
            }
        }

        public static string BekendeSoort(string soort)
        {
            return Array.IndexOf(soorten, soort) >= 0 ? soort : "onleesbaar";
        }

        public static string Reden(string soort)
        {
            int index = Array.IndexOf(soorten, soort);
            return zinnen[index >= 0 ? index : Array.IndexOf(soorten, "onleesbaar")];
        }

        private static bool AsciiLetter(char teken)
        {
            return (teken >= 'A' && teken <= 'Z') || (teken >= 'a' && teken <= 'z');
        }

        // ---- stap 1: spelling

        public static void ControleerSpelling(string tekst)
        {
            if (tekst == null) { throw new PadGeweigerd("onleesbaar", null, "geen tekst"); }
            string gespeld = tekst.Replace('/', '\\');
            string rest = gespeld;
            if (gespeld.StartsWith("\\\\", StringComparison.Ordinal))
            {
                Match station = lokaalApparaatStation.Match(gespeld);
                Match guid = lokaleVolumeGuid.Match(gespeld);
                if (station.Success) { rest = gespeld.Substring(4); }
                else if (guid.Success) { rest = gespeld.Substring(guid.Index + guid.Length); }
                else
                {
                    string soort = uncVoorvoegsel.IsMatch(gespeld) ? "netwerkpad" : "apparaatpad";
                    throw new PadGeweigerd(soort, tekst, SPELLING_NETWORK_OR_DEVICE);
                }
            }
            if (rest.Length >= 2 && rest[1] == ':' && AsciiLetter(rest[0])) { rest = rest.Substring(2); }
            if (rest.IndexOf(':') >= 0) { throw new PadGeweigerd("stroom", tekst, SPELLING_STREAM); }
            foreach (string deel in rest.Split('\\'))
            {
                if (deel != "" && deel != "." && deel != ".." && (deel[deel.Length - 1] == '.' || deel[deel.Length - 1] == ' '))
                {
                    throw new PadGeweigerd("onleesbaar", tekst, SPELLING_DOT_OR_SPACE);
                }
            }
        }

        private static List<string> Splits(string tekst, out string sleutel)
        {
            ControleerSpelling(tekst);
            if (tekst.IndexOf('\0') >= 0) { throw new PadGeweigerd("onleesbaar", tekst, "nul-teken"); }
            if (tekst.IndexOf('/') >= 0) { throw new PadGeweigerd("onleesbaar", tekst, "schuine streep"); }
            string origineel = tekst;
            if (lokaalApparaatStation.IsMatch(tekst)) { tekst = tekst.Substring(4); }
            Match guid = lokaleVolumeGuid.Match(tekst);
            string staart;
            if (guid.Success)
            {
                sleutel = tekst.Substring(4, guid.Index + guid.Length - 4).TrimEnd('\\');
                staart = tekst.Substring(guid.Index + guid.Length);
            }
            else if (tekst.Length >= 3 && AsciiLetter(tekst[0]) && tekst[1] == ':' && tekst[2] == '\\')
            {
                sleutel = tekst.Substring(0, 2).ToUpperInvariant();
                staart = tekst.Substring(3);
            }
            else if (tekst.Length == 2 && AsciiLetter(tekst[0]) && tekst[1] == ':')
            {
                throw new PadGeweigerd("onleesbaar", origineel, "schijf zonder map");
            }
            else
            {
                throw new PadGeweigerd("onleesbaar", origineel, "niet absoluut");
            }
            return Onderdelen(staart, origineel);
        }

        private static List<string> Onderdelen(string staart, string tekst)
        {
            List<string> delen = new List<string>();
            if (staart == "") { return delen; }
            delen.AddRange(staart.Split('\\'));
            if (delen[delen.Count - 1] == "") { delen.RemoveAt(delen.Count - 1); }
            foreach (string deel in delen)
            {
                if (deel == "" || deel == "." || deel == "..") { throw new PadGeweigerd("onleesbaar", tekst, "leeg of punt-onderdeel"); }
                if (deel.IndexOf(':') >= 0) { throw new PadGeweigerd("stroom", tekst, SPELLING_STREAM); }
                if (deel.Length > MaxOnderdeel) { throw new PadGeweigerd("onleesbaar", tekst, "onderdeel te lang"); }
            }
            return delen;
        }

        private static string Voeg(string sleutel, List<string> delen)
        {
            string basis = sleutel.EndsWith(":", StringComparison.Ordinal) ? sleutel + "\\" : "\\\\?\\" + sleutel + "\\";
            return basis + string.Join("\\", delen.ToArray());
        }

        private static List<string> Binnen(string sleutel, List<string> delen, string wortel)
        {
            string wortelSleutel;
            List<string> wortelDelen = Splits(wortel, out wortelSleutel);
            bool gelijk = string.Equals(wortelSleutel.ToUpperInvariant(), sleutel.ToUpperInvariant(), StringComparison.Ordinal)
                && delen.Count >= wortelDelen.Count;
            for (int i = 0; gelijk && i < wortelDelen.Count; i++)
            {
                if (!string.Equals(delen[i], wortelDelen[i], StringComparison.Ordinal)) { gelijk = false; }
            }
            if (!gelijk) { throw new PadGeweigerd("buiten_wortel", Voeg(sleutel, delen), ""); }
            List<string> uit = new List<string>(wortelDelen);
            uit.AddRange(delen.GetRange(wortelDelen.Count, delen.Count - wortelDelen.Count));
            return uit;
        }

        // ---- stap 2: het volume, zonder het pad of het volume te openen

        private static string Volumedoel(string sleutel, string pad)
        {
            string wortelTekst = sleutel.EndsWith(":", StringComparison.Ordinal) ? sleutel + "\\" : "\\\\?\\" + sleutel + "\\";
            uint type = Inheems.Stationstype(wortelTekst);
            if (type == DRIVE_REMOTE) { throw new PadGeweigerd("netwerkstation", pad, VOLUME_REMOTE); }
            if (type != DRIVE_FIXED) { throw new PadGeweigerd("apparaatpad", pad, "stationstype " + type); }
            string[] doelen = Inheems.Apparaatdoelen(sleutel);
            if (doelen == null || doelen.Length != 1) { throw new PadGeweigerd("apparaatpad", pad, "apparaatdoel niet eenduidig"); }
            string doel = doelen[0];
            if (harddiskVolume.IsMatch(doel)) { return doel; }
            string laag = doel.ToLowerInvariant();
            if (laag.StartsWith("\\device\\mup", StringComparison.Ordinal) || laag.Contains("redirector") || laag.StartsWith("\\??\\unc\\", StringComparison.Ordinal))
            {
                throw new PadGeweigerd("netwerkstation", pad, VOLUME_REMOTE);
            }
            throw new PadGeweigerd("apparaatpad", pad, "apparaatdoel");
        }

        // ---- een koppeling boven de wortel: alleen tekst

        private static PadGeweigerd Onleesbaar(string pad, string detail)
        {
            return new PadGeweigerd("onleesbaar", pad, detail);
        }

        private static string Koppelingsdoel(byte[] ruw, string sleutel, List<string> ouder, List<string> rest, string pad)
        {
            string vervanging;
            uint vlaggen;
            try
            {
                if (ruw.Length < 4) { throw Onleesbaar(pad, "koppelingsgegevens"); }
                uint tag = BitConverter.ToUInt32(ruw, 0);
                int basis;
                int offset;
                int lengte;
                if (tag == IO_REPARSE_TAG_SYMLINK)
                {
                    if (ruw.Length < 20) { throw Onleesbaar(pad, "koppelingsgegevens"); }
                    offset = BitConverter.ToUInt16(ruw, 8);
                    lengte = BitConverter.ToUInt16(ruw, 10);
                    vlaggen = BitConverter.ToUInt32(ruw, 16);
                    basis = 20;
                }
                else if (tag == IO_REPARSE_TAG_MOUNT_POINT)
                {
                    if (ruw.Length < 16) { throw Onleesbaar(pad, "koppelingsgegevens"); }
                    offset = BitConverter.ToUInt16(ruw, 8);
                    lengte = BitConverter.ToUInt16(ruw, 10);
                    vlaggen = 0;
                    basis = 16;
                }
                else
                {
                    throw new PadGeweigerd("herparseerpunt", pad, "tag 0x" + tag.ToString("X8"));
                }
                if (basis + offset + lengte > ruw.Length || lengte % 2 != 0) { throw Onleesbaar(pad, "koppelingsgegevens"); }
                vervanging = striktUtf16.GetString(ruw, basis + offset, lengte);
            }
            catch (ArgumentException)
            {
                throw Onleesbaar(pad, "koppelingsgegevens");
            }
            string staart = rest.Count > 0 ? "\\" + string.Join("\\", rest.ToArray()) : "";
            if ((vlaggen & SYMLINK_FLAG_RELATIVE) != 0)
            {
                if (vervanging.IndexOf('/') >= 0 || vervanging.IndexOf('\0') >= 0) { throw Onleesbaar(pad, "relatief koppelingsdoel"); }
                List<string> delen = vervanging.StartsWith("\\", StringComparison.Ordinal) ? new List<string>() : new List<string>(ouder);
                foreach (string deel in vervanging.Split('\\'))
                {
                    if (deel == "" || deel == ".") { continue; }
                    if (deel == "..")
                    {
                        if (delen.Count == 0) { throw Onleesbaar(pad, "relatief koppelingsdoel boven de schijf"); }
                        delen.RemoveAt(delen.Count - 1);
                        continue;
                    }
                    delen.Add(deel);
                }
                return Voeg(sleutel, delen) + staart;
            }
            if (vervanging.Length >= 8 && vervanging.Substring(0, 8).ToUpperInvariant() == "\\??\\UNC\\")
            {
                return "\\\\" + vervanging.Substring(8) + staart;
            }
            if (vervanging.StartsWith("\\??\\", StringComparison.Ordinal))
            {
                string restVan = vervanging.Substring(4).TrimEnd('\\');
                if (restVan.Length >= 2 && restVan[1] == ':')
                {
                    string tekst = restVan + staart;
                    return tekst.Length == 2 ? tekst + "\\" : tekst;
                }
                return "\\\\?\\" + restVan + staart;
            }
            return "\\\\?\\GLOBALROOT" + vervanging + staart;
        }

        // ---- status naar soort

        private static PadGeweigerd StatusWeigering(uint status, string pad)
        {
            PadGeweigerd weigering;
            if (status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND)
            {
                weigering = new PadGeweigerd("onleesbaar", pad, "afwezig");
            }
            else if (status == STATUS_NOT_A_DIRECTORY || status == STATUS_FILE_IS_A_DIRECTORY)
            {
                weigering = new PadGeweigerd("geen_gewoon_bestand", pad, "");
            }
            else if (status == STATUS_REPARSE || status == STATUS_STOPPED_ON_SYMLINK || status == STATUS_REPARSE_POINT_NOT_RESOLVED || status == STATUS_DIRECTORY_IS_A_REPARSE_POINT)
            {
                weigering = new PadGeweigerd("koppeling", pad, "");
            }
            else if (Array.IndexOf(netwerkstatussen, status) >= 0)
            {
                Console.Error.WriteLine(DefectRegel);
                weigering = new PadGeweigerd("netwerkpad", pad, "netwerkstatus");
            }
            else
            {
                weigering = new PadGeweigerd("onleesbaar", pad, "");
            }
            weigering.Status = status;
            return weigering;
        }

        private static void LogWeigering(PadGeweigerd fout)
        {
            if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("NSMCP_DEBUG"))) { return; }
            string status = fout.Status >= 0 ? "0x" + fout.Status.ToString("X8") : "-";
            Console.Error.WriteLine("[nsmcp-pad] geweigerd soort=" + fout.Soort + " status=" + status + " detail='" + fout.Detail + "' pad='" + fout.Pad + "'");
        }

        internal static void SluitAlles(List<IntPtr> handles)
        {
            while (handles.Count > 0)
            {
                IntPtr handle = handles[handles.Count - 1];
                handles.RemoveAt(handles.Count - 1);
                try { Inheems.Sluit(handle); } catch (Exception) { }
            }
        }

        // ---- stap 3 tot 6

        private sealed class Greep
        {
            public List<IntPtr> Keten;
            public IntPtr Blad;
            public long Grootte;
            public string Pad;
        }

        private static LokaalStroom AlsStroom(Greep greep)
        {
            if (greep == null) { return null; }
            bool overgedragen = false;
            try
            {
                LokaalStroom stroom = new LokaalStroom(greep.Blad, greep.Keten, greep.Pad, greep.Grootte);
                overgedragen = true;
                return stroom;
            }
            finally
            {
                if (!overgedragen)
                {
                    List<IntPtr> alles = new List<IntPtr>(greep.Keten);
                    alles.Add(greep.Blad);
                    SluitAlles(alles);
                }
            }
        }

        private static string[] Opsommen(Greep greep)
        {
            if (greep == null) { return null; }
            List<IntPtr> alles = new List<IntPtr>(greep.Keten);
            alles.Add(greep.Blad);
            try
            {
                List<string> namen = new List<string>();
                bool opnieuw = true;
                while (true)
                {
                    byte[] ruw;
                    uint status = Inheems.MapInhoud(greep.Blad, opnieuw, out ruw);
                    opnieuw = false;
                    if (status == STATUS_NO_MORE_FILES || status == STATUS_NO_SUCH_FILE) { break; }
                    if (status != 0)
                    {
                        PadGeweigerd mislukt = new PadGeweigerd("onleesbaar", greep.Pad, "map opsommen");
                        mislukt.Status = status;
                        throw mislukt;
                    }
                    int positie = 0;
                    while (true)
                    {
                        if (positie + 12 > ruw.Length) { throw Onleesbaar(greep.Pad, "mapgegevens"); }
                        uint volgende = BitConverter.ToUInt32(ruw, positie);
                        int lengte = (int)BitConverter.ToUInt32(ruw, positie + 8);
                        if (positie + 12 + lengte > ruw.Length || lengte % 2 != 0) { throw Onleesbaar(greep.Pad, "mapgegevens"); }
                        string naam;
                        try { naam = striktUtf16.GetString(ruw, positie + 12, lengte); }
                        catch (ArgumentException) { throw Onleesbaar(greep.Pad, "mapgegevens"); }
                        if (naam != "." && naam != "..") { namen.Add(naam); }
                        if (volgende == 0) { break; }
                        positie += (int)volgende;
                    }
                }
                return namen.ToArray();
            }
            finally
            {
                SluitAlles(alles);
            }
        }

        private static Greep Loop(string pad, string sleutel, List<string> delen, int wortelTelling, bool deelSchrijvers, bool magOntbreken, bool alsMap)
        {
            List<IntPtr> vast = new List<IntPtr>();
            bool overgedragen = false;
            try
            {
                string apparaat = Volumedoel(sleutel, pad);
                IntPtr handle;
                uint status = Inheems.Maak(IntPtr.Zero, apparaat + "\\", DIR_ACCESS, DIR_SHARE, FILE_OPEN, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, out handle);
                if (status != 0 || handle == IntPtr.Zero) { throw StatusWeigering(status, pad); }
                vast.Add(handle);
                if (Inheems.Bestandstype(handle) != FILE_TYPE_DISK) { throw new PadGeweigerd("netwerkpad", pad, "geen schijfhandle"); }
                uint apparaatType;
                uint kenmerken;
                status = Inheems.Apparaatinfo(handle, out apparaatType, out kenmerken);
                if (status != 0 || apparaatType != FILE_DEVICE_DISK || (kenmerken & FILE_REMOTE_DEVICE) != 0)
                {
                    PadGeweigerd geenSchijf = new PadGeweigerd("netwerkpad", pad, "geen lokaal schijfapparaat");
                    if (status != 0) { geenSchijf.Status = status; }
                    throw geenSchijf;
                }
                if (delen.Count == 0) { throw new PadGeweigerd(alsMap ? "onleesbaar" : "geen_gewoon_bestand", pad, "volumewortel"); }
                int laatste = delen.Count - 1;
                for (int index = 0; index < delen.Count; index++)
                {
                    string deel = delen[index];
                    if (Naad.Tussen != null) { Naad.Tussen(index, deel); }
                    bool isBlad = index == laatste;
                    uint toegang = DIR_ACCESS;
                    uint deling = DIR_SHARE;
                    uint opties = FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT;
                    if (isBlad && alsMap)
                    {
                        // Een map die zelf gevraagd wordt (om op te sommen): lijstrecht erbij.
                        toegang = DIR_LIST_ACCESS;
                    }
                    else if (isBlad)
                    {
                        toegang = LEAF_ACCESS;
                        deling = FILE_SHARE_READ | (deelSchrijvers ? FILE_SHARE_WRITE : 0);
                        opties = FILE_OPEN_REPARSE_POINT | FILE_SEQUENTIAL_ONLY | FILE_SYNCHRONOUS_IO_NONALERT;
                    }
                    status = Inheems.Maak(vast[vast.Count - 1], deel, toegang, deling, FILE_OPEN, opties, out handle);
                    if (status != 0 || handle == IntPtr.Zero)
                    {
                        if (magOntbreken && (status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND)) { return null; }
                        throw StatusWeigering(status, pad);
                    }
                    vast.Add(handle);
                    uint attributen;
                    uint tag;
                    status = Inheems.Tag(handle, deel, out attributen, out tag);
                    if (status != 0)
                    {
                        PadGeweigerd geenTag = new PadGeweigerd("onleesbaar", pad, "tag");
                        geenTag.Status = status;
                        throw geenTag;
                    }
                    if ((attributen & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                    {
                        bool binnen = wortelTelling >= 0 && index >= wortelTelling - 1;
                        bool isKoppeling = tag == IO_REPARSE_TAG_SYMLINK || tag == IO_REPARSE_TAG_MOUNT_POINT;
                        string detail = "tag 0x" + tag.ToString("X8") + " onderdeel " + index;
                        if (binnen) { throw new PadGeweigerd(isKoppeling ? "koppeling" : "herparseerpunt", pad, detail); }
                        if (!isKoppeling) { throw new PadGeweigerd("herparseerpunt", pad, detail); }
                        byte[] gegevens = Inheems.Koppelingsgegevens(handle);
                        if (gegevens == null) { throw Onleesbaar(pad, "koppelingsgegevens"); }
                        throw new Volg(Koppelingsdoel(gegevens, sleutel, delen.GetRange(0, index), delen.GetRange(index + 1, delen.Count - index - 1), pad));
                    }
                    bool isMap = (attributen & FILE_ATTRIBUTE_DIRECTORY) != 0;
                    if (isMap != (!isBlad || alsMap)) { throw new PadGeweigerd("geen_gewoon_bestand", pad, "onderdeel " + index); }
                }
                Greep greep = new Greep();
                greep.Pad = pad;
                greep.Blad = vast[vast.Count - 1];
                if (!alsMap)
                {
                    long grootte;
                    bool map;
                    uint namen;
                    status = Inheems.Standaard(greep.Blad, out grootte, out map, out namen);
                    if (status != 0)
                    {
                        PadGeweigerd geenInfo = new PadGeweigerd("onleesbaar", pad, "standaardinformatie");
                        geenInfo.Status = status;
                        throw geenInfo;
                    }
                    if (map) { throw new PadGeweigerd("geen_gewoon_bestand", pad, "blad is een map"); }
                    // B.2 stap 6 (revisie 3): een bestand binnen de wortel met een
                    // tweede naam op de schijf kan een bestand van buiten de
                    // goedgekeurde boom zijn; geweigerd op het vastgehouden blad
                    // voordat er een byte gelezen wordt. Zonder wortel geen regel.
                    if (wortelTelling >= 0 && namen > 1) { throw new PadGeweigerd("hardlink", pad, namen + " namen"); }
                    greep.Grootte = grootte;
                }
                greep.Keten = vast.GetRange(0, vast.Count - 1);
                overgedragen = true;
                return greep;
            }
            finally
            {
                if (!overgedragen) { SluitAlles(vast); }
            }
        }

        private static Greep Wandel(string pad, string wortel, bool deelSchrijvers, bool magOntbreken, bool alsMap)
        {
            if (pad == null) { throw new PadGeweigerd("onleesbaar", null, "geen tekst"); }
            string huidig = pad;
            int sprongen = 0;
            int wortelTelling = -1;
            try
            {
                while (true)
                {
                    string sleutel;
                    List<string> delen = Splits(huidig, out sleutel);
                    if (sprongen == 0 && wortel != null)
                    {
                        delen = Binnen(sleutel, delen, wortel);
                        string wortelSleutel;
                        wortelTelling = Splits(wortel, out wortelSleutel).Count;
                    }
                    try
                    {
                        return Loop(huidig, sleutel, delen, wortelTelling, deelSchrijvers, magOntbreken, alsMap);
                    }
                    catch (Volg volg)
                    {
                        sprongen++;
                        if (sprongen > KoppelingGrens) { throw new PadGeweigerd("te_veel_koppelingen", volg.Pad, ""); }
                        int voor = delen.Count;
                        huidig = volg.Pad;
                        string nieuweSleutel;
                        List<string> nieuw = Splits(huidig, out nieuweSleutel);
                        if (wortelTelling >= 0) { wortelTelling = nieuw.Count - (voor - wortelTelling); }
                    }
                }
            }
            catch (PadGeweigerd fout)
            {
                if (fout.Pad == null) { fout.Pad = huidig; }
                fout.Gevolgd = sprongen > 0;
                LogWeigering(fout);
                throw;
            }
        }

        // ---- publiek

        public static LokaalStroom Open(string pad, string wortel, bool deelSchrijvers, bool magOntbreken)
        {
            if (string.IsNullOrEmpty(wortel)) { throw new ArgumentException("wortel ontbreekt; gebruik OpenZonderWortel"); }
            return AlsStroom(Wandel(pad, wortel, deelSchrijvers, magOntbreken, false));
        }

        public static LokaalStroom OpenZonderWortel(string pad, bool deelSchrijvers, bool magOntbreken)
        {
            return AlsStroom(Wandel(pad, null, deelSchrijvers, magOntbreken, false));
        }

        // De namen in een map, gelezen op haar vastgehouden handle
        // (NtQueryDirectoryFile, FileNamesInformation): de spiegel van
        // localpath.list_local. Niets in de map wordt geopend; wat de
        // aanroeper daarna opent, gaat opnieuw door de wandeling. null als de
        // map ontbreekt en dat mag.
        public static string[] Namen(string pad, string wortel, bool magOntbreken)
        {
            if (string.IsNullOrEmpty(wortel)) { throw new ArgumentException("wortel ontbreekt; gebruik NamenZonderWortel"); }
            return Opsommen(Wandel(pad, wortel, true, magOntbreken, true));
        }

        public static string[] NamenZonderWortel(string pad, bool magOntbreken)
        {
            return Opsommen(Wandel(pad, null, true, magOntbreken, true));
        }

        public static string AbsoluteTekst(string tekst)
        {
            ControleerSpelling(tekst);
            if (!tekst.StartsWith("\\\\", StringComparison.Ordinal)) { tekst = tekst.Replace('/', '\\'); }
            if (striktAbsoluut.IsMatch(tekst)) { return tekst; }
            try
            {
                return Path.GetFullPath(tekst);
            }
            catch (Exception)
            {
                throw new PadGeweigerd("onleesbaar", tekst, "niet absoluut");
            }
        }

        public static string Onder(string wortelTekst, string naam)
        {
            List<string> stukken = new List<string>();
            stukken.Add(wortelTekst.TrimEnd('\\'));
            stukken.AddRange(Regex.Split(naam, @"[\\/]"));
            return string.Join("\\", stukken.ToArray());
        }

        public static string Sha256Hex(LokaalStroom stroom)
        {
            stroom.Position = 0;
            using (SHA256 sha = SHA256.Create())
            {
                byte[] digest = sha.ComputeHash(stroom);
                StringBuilder hex = new StringBuilder(64);
                foreach (byte b in digest) { hex.Append(b.ToString("x2")); }
                return hex.ToString();
            }
        }

        public static byte[] LeesBytes(LokaalStroom stroom, int max)
        {
            stroom.Position = 0;
            using (MemoryStream uit = new MemoryStream())
            {
                byte[] buffer = new byte[65536];
                long over = (long)max + 1;
                while (over > 0)
                {
                    int gelezen = stroom.Read(buffer, 0, (int)Math.Min(buffer.Length, over));
                    if (gelezen <= 0) { break; }
                    uit.Write(buffer, 0, gelezen);
                    over -= gelezen;
                }
                return uit.ToArray();
            }
        }
    }
}
'@
}

# Deelmodus van het blad per bestandsklasse ($true = FILE_SHARE_READ |
# FILE_SHARE_WRITE). Mappen op de weg altijd READ | WRITE, nooit DELETE.
$script:GjkLokaalDeelSchrijvers = @{
    bundel    = $false
    sidecar   = $false
    pakket    = $false
    ledger    = $true
    runnerlog = $true
}

function _GjkLokaalPadUitpakken {
    # Een .NET-aanroep vanuit PowerShell verpakt elke exceptie in een
    # MethodInvocationException; een weigering komt kaal terug.
    param([System.Management.Automation.ErrorRecord] $Fout)
    $uitzondering = $Fout.Exception
    if ($uitzondering -is [System.Management.Automation.MethodInvocationException] -and
        $uitzondering.InnerException -is [GjkLokaalPad.PadGeweigerd]) {
        return $uitzondering.InnerException
    }
    return $null
}

function Open-GjkLokaalBestand {
    <#  Opent -Pad onderdeel voor onderdeel (zie boven) en geeft een
        [GjkLokaalPad.LokaalStroom] terug: een FileStream op de vastgehouden
        bladhandle. De keten van vastgehouden mappen blijft open tot
        Close-GjkLokaalBestand. -Wortel: de goedgekeurde map (niets daarin,
        de wortel zelf inbegrepen, mag een herparseerpunt zijn); -ZonderWortel
        voor een configuratiepad zonder goedgekeurde map; precies een van de
        twee. -MagOntbreken: een ontbrekend onderdeel geeft $null in plaats van
        een weigering. Een weigering is een [GjkLokaalPad.PadGeweigerd]. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $Pad,
        [string] $Wortel = '',
        [switch] $ZonderWortel,
        [Parameter(Mandatory = $true)] [ValidateSet('bundel', 'sidecar', 'pakket', 'ledger', 'runnerlog')] [string] $Klasse,
        [switch] $MagOntbreken
    )
    if ($ZonderWortel.IsPresent -eq (-not [string]::IsNullOrEmpty($Wortel))) {
        throw (New-Object System.ArgumentException('Open-GjkLokaalBestand: geef precies een van -Wortel en -ZonderWortel'))
    }
    $deelSchrijvers = [bool]$script:GjkLokaalDeelSchrijvers[$Klasse]
    try {
        if ($ZonderWortel) {
            return [GjkLokaalPad.Wandeling]::OpenZonderWortel($Pad, $deelSchrijvers, $MagOntbreken.IsPresent)
        }
        return [GjkLokaalPad.Wandeling]::Open($Pad, $Wortel, $deelSchrijvers, $MagOntbreken.IsPresent)
    }
    catch {
        $weigering = _GjkLokaalPadUitpakken $_
        if ($null -ne $weigering) { throw $weigering }
        throw
    }
}

function Get-GjkLokaleNamen {
    <#  De namen in -Map, gelezen op de vastgehouden maphandle
        (NtQueryDirectoryFile; de spiegel van localpath.list_local): de map is
        haar eigen wortel (dezelfde tekst), dus een koppeling op haar plek of
        erin wordt geweigerd en een koppeling erboven pas gevolgd na de
        spelling- en volumetoets van het doel - nooit eerst een opsomming op
        naam. Niets in de map wordt geopend. Uitvoer: de namen, een per
        object (gebruik @(...)). -MagOntbreken: een ontbrekende map geeft geen
        namen in plaats van een weigering. #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [string] $Map, [switch] $MagOntbreken)
    try {
        $wortel = [GjkLokaalPad.Wandeling]::AbsoluteTekst($Map)
        $namen = [GjkLokaalPad.Wandeling]::Namen($wortel, $wortel, $MagOntbreken.IsPresent)
    }
    catch {
        $weigering = _GjkLokaalPadUitpakken $_
        if ($null -ne $weigering) { throw $weigering }
        throw
    }
    if ($null -eq $namen) { return }
    foreach ($naam in $namen) { Write-Output $naam }
}

function Close-GjkLokaalBestand {
    <#  Sluit het blad en daarna de keten, elke handle precies een keer, in
        omgekeerde volgorde. $null mag (niets geopend). #>
    param($Stroom)
    if ($null -ne $Stroom) { $Stroom.Dispose() }
}

function Join-GjkLokaalPad {
    <#  Wortel en pad uit DEZELFDE tekst: de wortel als absolute tekst (de
        spelling eerst, op de tekst zoals geschreven) en het pad als die tekst
        plus -Naam. De wandeling vergelijkt de twee ordinaal. #>
    param([Parameter(Mandatory = $true)] [string] $Map, [Parameter(Mandatory = $true)] [string] $Naam)
    try {
        $wortel = [GjkLokaalPad.Wandeling]::AbsoluteTekst($Map)
        return [pscustomobject]@{ Wortel = $wortel; Pad = [GjkLokaalPad.Wandeling]::Onder($wortel, $Naam) }
    }
    catch {
        $weigering = _GjkLokaalPadUitpakken $_
        if ($null -ne $weigering) { throw $weigering }
        throw
    }
}

function Get-GjkLokaleSha256 {
    <#  De sha256 van het vastgehouden blad, gelezen op zijn handle. #>
    param([Parameter(Mandatory = $true)] $Stroom)
    return [GjkLokaalPad.Wandeling]::Sha256Hex($Stroom)
}

function Read-GjkLokaleBytes {
    <#  Hoogstens -Max + 1 bytes van het vastgehouden blad; meer dan -Max is
        de plafondroute van de aanroeper. #>
    param([Parameter(Mandatory = $true)] $Stroom, [Parameter(Mandatory = $true)] [int] $Max)
    return , ([GjkLokaalPad.Wandeling]::LeesBytes($Stroom, $Max))
}

function Get-GjkLokaalPadSoort {
    <#  De soort van een weigering in een foutrecord, of '' als het geen
        weigering van deze functie is. #>
    param([Parameter(Mandatory = $true)] [System.Management.Automation.ErrorRecord] $Fout)
    if ($Fout.Exception -is [GjkLokaalPad.PadGeweigerd]) { return $Fout.Exception.Soort }
    $weigering = _GjkLokaalPadUitpakken $Fout
    if ($null -ne $weigering) { return $weigering.Soort }
    return ''
}

function Get-GjkLokaalPadReden {
    <#  De vaste zin van een soort: nooit een pad, een status of een regeleinde. #>
    param([Parameter(Mandatory = $true)] [string] $Soort)
    return [GjkLokaalPad.Wandeling]::Reden($Soort)
}
