"""Level-1 scorecard: 23 fixed controls plus confirmed IPREP scan context.

X counts PASS/FAIL only; Y excludes five external controls (18 or 19).
Severity belongs to each outcome, following released NSHC 1.0.1 branches.
Deliberate parity deviations: absent daystoexpiration is a read gap, never
PASS/Info; missing feature licence flags never establish non-applicability.
HA-004 consumes the current HA engine's hash-verified running/saved drift,
which provides stronger evidence than NSHC's constant unassessed placeholder.
Backup POLICY (L1-007) remains wholly outside Y. No advice is generated.
L1-013 follows the NSHC B-or-better threshold, superseding the old plan's
A/A+ sample. Unlike the legacy aggregator, mixed safe/unassessed grades never
yield a composite PASS; only an established C/F/T can establish FAIL.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from datetime import UTC, datetime

from nsmcp.answer import Answer, Certainty, Finding, NotAssessed, ReadGap
from nsmcp.coverage import coverage_of
from nsmcp.cve import GERAAKT, NIET_GERAAKT, cve_verdicts
from nsmcp.export import (
    MISSING,
    RUNNING_CONFIG_FILE,
    SAVED_CONFIG_FILE,
    SYSTEMUSER_RESOURCE,
    shape_or_missing,
)
from nsmcp.ha import DRIFT_LABEL, ha_result
from nsmcp.headers import header_coverage
from nsmcp.knowledge import Knowledge
from nsmcp.mgmt_plane import mgmt_plane_result
from nsmcp.rulesets import IPREP_BASELINE, SSL_BASELINE, ruleset_line
from nsmcp.tls_baseline import NOT_ASSESSED_WORD, baseline_result, grade_per_vserver

STATUS_WORDS = ("PASS", "FAIL", "NIET BEOORDEELD")
SEVERITY_WORDS = ("Kritiek", "Hoog", "Midden", "Laag", "Info")
CONFIDENCE_WORDS = ("hoog", "gemiddeld", "laag", "niet vastgesteld")
APPLICABILITY_WORDS = ("van toepassing", "niet van toepassing", "invoer nodig", "onbekend")
NB = STATUS_WORDS[2]
OUT_OF_DENOMINATOR = ("GJK-L1-004", "GJK-L1-007", "GJK-L1-009", "GJK-L1-011", "GJK-L1-012")
OUT_OF_SCOPE = (
    ("Console-klantseparatie (GJK-L1-004)", "vraagt de Console-API, niet appliance-NITRO"),
    ("Console-agent-standaard (GJK-L1-009)", "idem; alleen leesbaar via de Console-API of de shell"),
    ("secrets- en bestandshygiene (GJK-L1-011)", "vraagt het bestandssysteem van de appliance"),
    ("DevOps als source of truth (GJK-L1-012)", "procesvraag, geen configuratievraag"),
    (
        "backupbeleid (GJK-L1-007)",
        "de drift-helft is wel beantwoord uit runningconfig tegenover savedconfig; het beleid zelf staat niet in een export",
    ),
    ("live gezondheid", "stat/ns, stat/system en stat/lbvserver zitten niet in de 58 resources van de collector"),
    (
        "TCP TimeStamp op een gebonden profiel",
        "config/nstcpprofile zit niet in deze export; met die resource erbij vervalt dit onderwerp",
    ),
)


@dataclass(frozen=True)
class Control:
    id: str
    title: str
    conditional: bool = False


CONTROLS = (
    tuple(
        Control(f"GJK-L1-{i:03}", title)
        for i, title in enumerate(
            (
                "Management-plane-isolatie",
                "Admin transport en default-certificaten",
                "RBAC en break-glass",
                "Console-klantseparatie",
                "NTP, DNS en SNMP-basisconfiguratie",
                "Audit/syslog policies en actions (appliance-side)",
                "Backupbeleid en config-audit",
                "Firmwarepositie",
                "Console-agent-standaard",
                "TLS/SSL-baseline",
                "Secrets en bestandshygiene",
                "DevOps als source of truth",
                "SSL/TLS-grading per vserver",
                "Bekende CVE-status",
            ),
            1,
        )
    )
    + tuple(
        Control(f"GJK-L1-HA-{i:03}", title)
        for i, title in enumerate(
            (
                "HA-rolverdeling",
                "HA-propagatie en sync",
                "Geen geforceerde HA-node-state",
                "HA running-vs-saved config-drift",
            ),
            1,
        )
    )
    + (
        Control("ANNA-LIC-001", "Licentie-assessment"),
        Control("ANNA-SEC-HTTP-HEADERS-001", "HTTP-security-headers"),
        Control("ANNA-SEC-APPFW-VPN-001", "WAF/AppFirewall op Gateway/VPN"),
        Control("ANNA-SEC-IPREP-001", "IP-reputation"),
        Control("ANNA-SEC-BOTMGMT-001", "Bot-management"),
        Control("ANNA-SEC-IPREP-SCAN-001", "IP-reputation: waargenomen werking", True),
    )
)


@dataclass(frozen=True)
class ControlResult:
    control: Control
    status: str
    severity: str
    applicability: str
    confidence: str
    evidence: str
    reason: str = ""
    in_denominator: bool = True
    read_gaps: tuple[ReadGap, ...] = ()


def _result(control, status, severity, evidence, gaps=(), *, reason="", applicability=None):
    gaps = tuple(dict.fromkeys((g.source, g.reason) for g in gaps))
    read_gaps = tuple(ReadGap(source=s, reason=r) for s, r in gaps)
    return ControlResult(
        control,
        status,
        severity,
        applicability or ("onbekend" if status == NB else "van toepassing"),
        "niet vastgesteld" if status == NB else "hoog",
        evidence,
        reason or "; ".join(g.reason for g in read_gaps),
        control.id not in OUT_OF_DENOMINATOR,
        read_gaps,
    )


def _field_gap(row, field, resource):
    return ReadGap(
        source=resource, reason=f"veld {field} niet bruikbaar gelezen ({shape_or_missing(row.get(field, MISSING))})"
    )


def _single(export, resource):
    row, gap = export.single(resource)
    if gap is not None:
        return {}, (gap,)
    if row is None:
        return {}, (ReadGap(source=resource, reason="gelezen maar leeg; vereist object ontbreekt"),)
    return row, ()


def _switch(export, resource, field):
    row, gaps = _single(export, resource)
    if gaps:
        return None, gaps
    value = row.get(field, MISSING)
    if type(value) is bool:
        return value, ()
    if type(value) is int and value in (0, 1):
        return value == 1, ()
    if isinstance(value, str):
        token = value.strip().lower()
        if token in ("true", "yes", "1", "enabled"):
            return True, ()
        if token in ("false", "no", "0", "disabled"):
            return False, ()
    return None, (_field_gap(row, field, resource),)


def _rows(export, resources):
    result, gaps = {}, []
    for resource in resources:
        rows, gap = export.objects(resource)
        result[resource] = rows
        if gap:
            gaps.append(gap)
    return result, gaps


def _number(value, *, negative=False):
    if type(value) is int:
        return value if negative or value >= 0 else None
    if isinstance(value, str) and re.fullmatch(r"-?\d{1,10}" if negative else r"\d{1,10}", value):
        return int(value)
    return None


def _license(control, export):
    row, gaps = _single(export, "config/nslicense")
    days = _number(row.get("daystoexpiration"), negative=True)
    if gaps:
        return _result(control, NB, "Hoog", "config/nslicense", gaps)
    if days is None:
        reason = (
            "daystoexpiration ontbreekt in config/nslicense"
            if "daystoexpiration" not in row
            else "daystoexpiration niet bruikbaar in config/nslicense"
        )
        if row.get("licensingmode") == "EXPRESS":
            reason += " (licensingmode EXPRESS)"
        gap = _field_gap(row, "daystoexpiration", "config/nslicense")
        return _result(control, NB, "Hoog", "config/nslicense", (gap,), reason=reason)
    return _result(
        control,
        "FAIL" if days <= 30 else "PASS",
        "Hoog" if days <= 0 else "Midden" if days <= 30 else "Info",
        f"config/nslicense: verloopt over {days} dagen",
    )


def _management(control, export, dimensions):
    chosen = (
        (dimensions["transport"], dimensions["certificaat"]) if control.id.endswith("002") else (dimensions["RBAC"],)
    )
    gaps = []
    for dimension in chosen:
        for unread in dimension.unread:
            resource = unread.split(" (", 1)[0]
            if resource == SYSTEMUSER_RESOURCE:
                _, gap = export.systemuser_rows()
            elif resource.endswith(".json"):
                _, gap = export.bindings(resource)
            else:
                _, gap = export.objects(resource)
                if gap:
                    _, single_gap = export.single(resource)
                    if single_gap is None:
                        gap = None
            gaps.append(gap or ReadGap(source=resource, reason=unread))
        # B5 (1.0.2): the parent cross-check gaps of the dimension too.
        gaps.extend(dimension.gaps)
    status = (
        "FAIL"
        if any(d.verdict == "FAIL" for d in chosen)
        else NB
        if gaps or any(d.verdict == NB for d in chosen)
        else "PASS"
    )
    return _result(control, status, "Hoog", "; ".join(d.evidence for d in chosen), gaps)


def _basic(control, export):
    resources = (
        ("config/ntpserver", "config/dnsnameserver", "config/snmpcommunity", "config/snmpmanager")
        if control.id.endswith("005")
        else ("config/auditsyslogpolicy", "config/auditsyslogaction")
    )
    rows, gaps = _rows(export, resources)
    public = False
    for row in rows.get("config/snmpcommunity", []):
        value = row.get("communityname")
        if not isinstance(value, str) or not value.strip():
            gaps.append(_field_gap(row, "communityname", "config/snmpcommunity"))
        elif value == "public":
            public = True
    evidence = "; ".join(f"{r}: {len(rows[r])} objecten" for r in resources)
    fail = not rows[resources[0]] or not rows[resources[1]] or public
    return _result(
        control,
        NB if gaps else "FAIL" if fail else "PASS",
        "Midden" if control.id.endswith("005") else "Hoog",
        evidence,
        gaps,
    )


def _feature_control(control, export, feature):
    licensed, gaps = _switch(export, "config/nslicense", feature)
    if licensed is None:
        return _result(control, NB, "Midden", f"config/nslicense.{feature}", gaps)
    if licensed is False:
        return _result(
            control,
            NB,
            "Info",
            f"config/nslicense.{feature}: niet gelicentieerd",
            reason="expliciet niet gelicentieerd",
            applicability="niet van toepassing",
        )
    enabled, gaps = _switch(export, "config/nsfeature", feature)
    if enabled is None:
        return _result(control, NB, "Midden", f"config/nsfeature.{feature}", gaps)
    if feature == "appfw":
        return _appfw(control, export, enabled)
    if feature == "bot":
        return _bot(control, export, enabled)
    resources = tuple(f"config/{name}policy" for name in ("responder", "rewrite", "appfw", "cs"))
    rows, gaps = _rows(export, resources)
    hits = 0
    for resource, policies in rows.items():
        for policy in policies:
            value = policy.get("rule")
            if not isinstance(value, str) or not value.strip():
                gaps.append(_field_gap(policy, "rule", resource))
            elif re.search(IPREP_BASELINE.rules["iprepExpressionPattern"], value):
                hits += 1
    evidence = f"config/nsfeature.rep: {'aan' if enabled else 'uit'}; {hits} IPREP-policyexpressies"
    if hits:
        return _result(control, "PASS" if enabled else "FAIL", "Info" if enabled else "Hoog", evidence, gaps)
    return _result(control, NB if gaps else "FAIL", "Midden" if gaps or enabled else "Laag", evidence, gaps)


def _appfw(control, export, enabled):
    rows, scope_gaps = _rows(export, ("config/vpnvserver", "config/authenticationvserver"))
    if not any(rows.values()):
        return _result(
            control,
            NB,
            "Midden" if scope_gaps else "Info",
            "Gateway/AAA-scope",
            scope_gaps,
            reason="Gateway/AAA-scope niet gelezen" if scope_gaps else "geen Gateway/AAA-vservers",
            applicability="onbekend" if scope_gaps else "niet van toepassing",
        )
    row, gaps = _single(export, "config/aaaparameter")
    value = row.get("wafprotection")
    members = value if isinstance(value, list) else [value]
    tokens = set(members) if all(isinstance(v, str) for v in members) else set()
    known = bool(tokens) and tokens <= {"DEFAULT", "AUTH", "VPN", "PORTAL", "DISABLED"}
    known = known and not ("DISABLED" in tokens and len(tokens) > 1)
    protected = known and bool(tokens & {"DEFAULT", "AUTH", "VPN"})
    if not known and not gaps:
        gaps = (_field_gap(row, "wafprotection", "config/aaaparameter"),)
    bindings, bind_gaps = _rows(
        export,
        (
            "config/vpnvserver_appfwpolicy_binding?bulkbindings=yes",
            "config/authenticationvserver_appfwpolicy_binding?bulkbindings=yes",
        ),
    )
    direct = False
    for resource, values in bindings.items():
        for binding in values:
            if isinstance(binding.get("policyname"), str) and binding["policyname"].strip():
                direct = True
            else:
                bind_gaps.append(_field_gap(binding, "policyname", resource))
    all_gaps = (*scope_gaps, *gaps, *bind_gaps)
    evidence = "Gateway/AAA aanwezig; wafprotection of directe AppFW-binding"
    if protected or direct:
        return _result(control, "PASS" if enabled else "FAIL", "Info" if enabled else "Hoog", evidence, all_gaps)
    return _result(control, NB if all_gaps else "FAIL", "Midden", evidence, all_gaps)


def _bot(control, export, enabled):
    resources = (
        "config/botprofile",
        "config/botpolicy",
        "config/botsettings",
        "config/lbvserver_botpolicy_binding?bulkbindings=yes",
        "config/csvserver_botpolicy_binding?bulkbindings=yes",
        "config/botglobal_botpolicy_binding",
    )
    rows, gaps = _rows(export, tuple(r for r in resources if r != "config/botsettings"))
    _, settings_gaps = _single(export, "config/botsettings")
    gaps.extend(settings_gaps)
    names, bound = set(), set()
    custom = 0
    for row in rows[resources[0]]:
        value = row.get("feature")
        if not isinstance(value, str) or not value.strip():
            gaps.append(_field_gap(row, "feature", resources[0]))
        elif value != "SYSTEM":
            custom += 1
    for resource in (resources[1], *resources[3:]):
        key = "name" if resource == resources[1] else "policyname"
        for row in rows[resource]:
            value = row.get(key)
            if not isinstance(value, str) or not value.strip():
                gaps.append(_field_gap(row, key, resource))
            else:
                (names if key == "name" else bound).add(value)
    correlated = names & bound
    configured = bool(names or bound or custom)
    evidence = f"botpolicy: {len(names)}; gebonden en gecorreleerd: {len(correlated)}; custom profielen: {custom}"
    if enabled and correlated:
        return _result(control, "PASS", "Info", evidence, gaps)
    if not enabled and configured:
        return _result(control, "FAIL", "Hoog", evidence, gaps)
    return _result(control, NB if gaps else "FAIL", "Midden" if gaps or enabled else "Laag", evidence, gaps)


def _scan(control, export, *, now):
    enabled, feature_gaps = _switch(export, "config/nsfeature", "rep")
    if enabled is not True:
        return _result(
            control,
            NB,
            "Midden",
            "config/nsfeature.rep niet bevestigd aan",
            feature_gaps,
            reason="scancontext vereist bevestigd ingeschakelde rep-feature",
        )
    if IPREP_BASELINE.rules.get("patternsConfirmed") is not True:
        gap = ReadGap(source="nshc-iprep-baseline", reason="scanpatronen niet bevestigd")
        return _result(control, NB, "Midden", "IPREP-regelset", (gap,))
    value, gap = export.iprep_scan_projection()
    if gap:
        return _result(control, NB, "Midden", "parsed/iprep-scan.json", (gap,))
    if value is None:
        return _result(
            control,
            NB,
            "Info",
            "scanlog afwezig",
            reason="originele resource meldt NOT_SUPPORTED",
            applicability="invoer nodig",
        )
    gaps = []
    errors = _number(value.get("errorLineCount"))
    age = _number(value.get("lastUpdateAgeMinutes"))
    for key, number in (("errorLineCount", errors), ("lastUpdateAgeMinutes", age)):
        if number is None:
            gaps.append(_field_gap(value, key, "parsed/iprep-scan.json"))
    categories = value.get("errorCategories")
    categories_valid = isinstance(categories, list) and all(
        isinstance(v, str) and v in ("auth", "dns", "connect", "other") for v in categories
    )
    if not categories_valid:
        gaps.append(_field_gap(value, "errorCategories", "parsed/iprep-scan.json"))
    # NSHC precedence: established database errors precede freshness. A
    # missing update timestamp is normal after a failed first download.
    if errors is not None and errors > 0 and categories_valid:
        return _result(control, "FAIL", "Hoog", f"scanprojectie: {errors} databasefouten", gaps)
    if gaps:
        return _result(control, NB, "Midden", "parsed/iprep-scan.json", gaps)
    try:
        stamp = datetime.fromisoformat(export.collected_at.replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            raise ValueError
        age += max(0, int((now - stamp).total_seconds() // 60))
    except (AttributeError, TypeError, ValueError):
        return _result(
            control,
            NB,
            "Midden",
            "exportmanifest",
            (
                ReadGap(
                    source="export-manifest.json",
                    reason="collectedAtUtc ontbreekt of is onbruikbaar; databaseleeftijd onbekend",
                ),
            ),
        )
    stale = age > IPREP_BASELINE.rules["staleAfterMinutes"]
    return _result(
        control,
        "FAIL" if stale else "PASS",
        "Midden" if stale else "Info",
        f"databaseleeftijd inclusief tijd sinds export: {age} minuten",
    )


def scorecard_results(export, knowledge: Knowledge, *, now: datetime | None = None) -> tuple[ControlResult, ...]:
    now = now or datetime.now(UTC)
    dimensions = {d.name: d for d in mgmt_plane_result(export)}
    ha, ha_gaps = ha_result(export)
    grades = grade_per_vserver(export)
    headers = header_coverage(export)
    records, cve_gaps = cve_verdicts(export, knowledge)
    results = []
    for c in CONTROLS:
        suffix = c.id.removeprefix("GJK-L1-")
        if c.id in OUT_OF_DENOMINATOR:
            r = _result(
                c,
                NB,
                "Hoog" if suffix == "011" else "Midden",
                "buiten het bereik van deze meting",
                reason="zie de vaste sectie",
                applicability="invoer nodig",
            )
        elif suffix in ("001", "008"):
            resource = "config/nsip" if suffix == "001" else "config/nsversion"
            if suffix == "001":
                rows, gap = export.objects(resource)
                gaps = (
                    (gap,)
                    if gap
                    else ()
                    if rows
                    else (ReadGap(source=resource, reason="gelezen maar leeg; isolatie niet vast te stellen"),)
                )
            else:
                _, gaps = _single(export, resource)
            r = _result(
                c,
                NB,
                "Hoog",
                resource,
                gaps,
                reason="isolatie vraagt extern netwerkbewijs"
                if suffix == "001"
                else "firmware-lifecycle vraagt extern beleid",
                applicability="onbekend" if gaps else "invoer nodig",
            )
        elif suffix in ("002", "003"):
            r = _management(c, export, dimensions)
        elif suffix in ("005", "006"):
            r = _basic(c, export)
        elif suffix.startswith("HA-"):
            d = ha.dimensions[int(suffix[-3:]) - 1]
            gaps = (d.read_gap,) if d.read_gap else tuple(g for g in ha_gaps if not d.established)
            status = (
                NB
                if not d.established or d.read_gap
                else "FAIL"
                if d.blocking
                else "PASS"
                if d.state == d.safe_state
                else NB
            )
            if status == NB and d.state != "niet van toepassing" and not gaps:
                # config-drift without a read gap of its own is `onbevestigd`
                # because lines whose value the collector withheld could
                # carry an unsaved change: the source that falls short is the
                # pair of config texts, never `config/hanode`.
                source = f"{RUNNING_CONFIG_FILE} en {SAVED_CONFIG_FILE}" if d.label == DRIFT_LABEL else "config/hanode"
                gaps = (ReadGap(source=source, reason=d.reason),)
            r = _result(
                c,
                status,
                "Midden" if suffix in ("HA-002", "HA-004") else "Hoog",
                d.evidence,
                gaps,
                reason=d.reason,
                applicability="niet van toepassing" if d.state == "niet van toepassing" else None,
            )
        elif suffix == "010":
            baseline = baseline_result(export)
            r = _result(
                c, baseline.status, "Hoog", "; ".join(item.evidence for item in baseline.criteria), baseline.read_gaps
            )
        elif suffix == "013":
            gaps = [g.read_gap for g in grades if g.read_gap]
            gaps.extend(
                ReadGap(source="config/sslvserver", reason=g.reason or "grade niet beoordeelbaar")
                for g in grades
                if g.letter == NOT_ASSESSED_WORD and not g.read_gap
            )
            _, source_gap = export.objects("config/sslvserver")
            if source_gap:
                gaps.append(source_gap)
            unknown = any(g.letter == NOT_ASSESSED_WORD for g in grades)
            letters = {g.letter for g in grades if g.letter != NOT_ASSESSED_WORD and not g.read_gap}
            fail = bool(letters & {"C", "F", "T"})
            status = "FAIL" if fail else NB if gaps or unknown or not letters else "PASS"
            severity = "Hoog" if fail and letters & {"F", "T"} else "Midden" if fail or gaps or unknown else "Info"
            r = _result(
                c,
                status,
                severity,
                f"{len(grades)} TLS-vservers; {ruleset_line(SSL_BASELINE)}",
                gaps,
                reason="geen beoordeelbare TLS-vservers" if status == NB else "",
                applicability="niet van toepassing" if not grades and not gaps else None,
            )
        elif suffix == "014":
            hit = [record for record in records if record.verdict == GERAAKT]

            def valid_score(value):
                return type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 10

            hard = any(valid_score(record.cvss) and record.cvss >= 7 for record in hit)
            unread_severity = any(not valid_score(record.cvss) for record in hit) and not hard
            clear = bool(records) and all(record.verdict == NIET_GERAAKT for record in records)
            gaps = list(cve_gaps)
            if unread_severity:
                gaps.extend(
                    ReadGap(source="kennispakket", reason=f"CVE cvss niet bruikbaar ({shape_or_missing(record.cvss)})")
                    for record in hit
                    if not valid_score(record.cvss)
                )
            if not hit and not clear and not gaps:
                gaps.append(
                    ReadGap(
                        source="kennispakket" if not records else "config/nsversion",
                        reason="geen sluitend gestructureerd CVE-oordeel beschikbaar",
                    )
                )
            r = _result(
                c,
                NB if unread_severity else "FAIL" if hit else "PASS" if clear else NB,
                "Hoog" if hard else "Midden" if hit or not clear else "Info",
                f"{len(records)} CVE-verdicts; kennispakket",
                gaps,
            )
        elif c.id == "ANNA-LIC-001":
            r = _license(c, export)
        elif c.id == "ANNA-SEC-HTTP-HEADERS-001":
            gaps = [g for h in headers for g in h.read_gaps]
            count = sum(h.word == "aanwezig en gebonden" for h in headers)
            status = (
                NB if gaps or any(h.word == "niet beoordeeld" for h in headers) else "PASS" if count >= 4 else "FAIL"
            )
            r = _result(
                c,
                status,
                "Hoog" if status == NB or not count else "Laag" if status == "PASS" else "Midden",
                f"{count} van {len(headers)} headers aanwezig en gebonden",
                gaps,
            )
        elif c.conditional:
            enabled, _ = _switch(export, "config/nsfeature", "rep")
            if enabled is not True:
                continue
            r = _scan(c, export, now=now)
        else:
            feature = {"ANNA-SEC-APPFW-VPN-001": "appfw", "ANNA-SEC-IPREP-001": "rep", "ANNA-SEC-BOTMGMT-001": "bot"}[
                c.id
            ]
            r = _feature_control(c, export, feature)
        results.append(r)
    return tuple(results)


def scorecard_answer(export, knowledge: Knowledge, *, now: datetime | None = None) -> Answer:
    results = scorecard_results(export, knowledge, now=now)
    denominator = [r for r in results if r.in_denominator]
    assessed = sum(r.status in ("PASS", "FAIL") for r in denominator)
    findings = [
        Finding(
            subject="scorekaart",
            outcome=f"{assessed} van {len(denominator)} beoordeeld, 5 controls buiten het bereik van deze meting",
            certainty=Certainty.ESTABLISHED,
            evidence=f"dekking van deze export: {coverage_of(export).verdict}",
            subject_is_name=False,
        )
    ]
    gaps = []
    for r in results:
        findings.append(
            Finding(
                subject=r.control.id,
                outcome=f"{r.status} - ernst {r.severity}, zekerheid {r.confidence}, {r.applicability}",
                certainty=Certainty.NOT_ESTABLISHED if r.status == NB else Certainty.ESTABLISHED,
                evidence=f"{r.control.title}; {r.evidence}",
                reason=r.reason or ("niet uit deze export te beantwoorden" if r.status == NB else ""),
                subject_is_name=False,
            )
        )
        gaps.extend(r.read_gaps)
    for rules in (SSL_BASELINE, IPREP_BASELINE):
        findings.append(
            Finding(
                subject="regelset",
                outcome=ruleset_line(rules),
                evidence="gevendorde NSHC-regels",
                certainty=Certainty.ESTABLISHED,
                subject_is_name=False,
            )
        )
    version = knowledge.version
    if isinstance(version, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", version):
        findings.append(
            Finding(
                subject="CVE-regels",
                outcome=f"kennispakketversie {version}",
                evidence="geladen kennispakket",
                certainty=Certainty.ESTABLISHED,
                subject_is_name=False,
            )
        )
    unique = {(g.source, g.reason): g for g in gaps}
    return Answer(
        question="hoe staat deze doos er qua hardening voor",
        findings=findings,
        read_gaps=list(unique.values()),
        not_assessed=[NotAssessed(subject=s, reason=r) for s, r in OUT_OF_SCOPE],
        knowledge_age_days=knowledge.age_days,
        knowledge_date=knowledge.date,
    )
