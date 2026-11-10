#!/usr/bin/env python3
"""Build catalog v2 from reviewed publisher artifacts (development: PyYAML 6.0.3).

Runtime is offline. Source refreshes are explicit and checksum-locked.
"""
import argparse
import collections
import hashlib
import io
import json
import re
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("--cache", type=Path, default=Path("/tmp/security-graph-catalog-sources"))
parser.add_argument("--update-sources", action="store_true")
parser.add_argument("--check", action="store_true")
args = parser.parse_args()
args.cache.mkdir(parents=True, exist_ok=True)
lock_path = ROOT / "pkg/catalog/sources.lock.json"
previous = json.loads(lock_path.read_text()) if lock_path.exists() else {}
sources = {}


def fetch(key, url):
    cache = args.cache / (key + ".source")
    if cache.exists():
        data = cache.read_bytes()
    else:
        request = urllib.request.Request(url, headers={"User-Agent": "Security-Graph-Catalog/2"})
        data = urllib.request.urlopen(request, timeout=60).read()
        cache.write_bytes(data)
    record = {"url": url, "sha256": hashlib.sha256(data).hexdigest()}
    if not args.update_sources and previous.get(key) != record:
        raise ValueError("Unreviewed source: " + key + "; refresh checksums only for a reviewed release")
    sources[key] = record
    return data


def plain(value):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", value or "")).strip()


v1 = json.loads((ROOT / "pkg/catalog/v1.json").read_text())
catalog = {"notices": [{"source": "CWE", "text": (ROOT/"pkg/catalog/CWE-LICENSE.txt").read_text()}, {"source": "Catalog sources", "text": (ROOT/"pkg/catalog/NOTICE.md").read_text()}], "version": "2", "released_at": "2026-11-10T00:00:00Z", "types": [], "frameworks": [], "entries": [], "mappings": []}
types, entries, mappings = {}, {}, {}


def framework(id, name, release, url, kind, coverage, license_url):
    catalog["frameworks"].append(dict(id=id, name=name, release=release, source_url=url, kind=kind, coverage=coverage, license_url=license_url))


def entry(framework_id, external, name, kind, url, description="", deprecated=False, parents=None):
    id = framework_id + ":" + external
    if id in entries:
        raise ValueError("Duplicate entry: " + id)
    entries[id] = dict(id=id, framework=framework_id, external_id=external, name=name, kind=kind, source_url=url)
    if description:
        entries[id]["description"] = plain(description)[:600]
    if deprecated:
        entries[id]["deprecated"] = True
    if parents:
        entries[id]["parents"] = parents
    return id


def mapping(type_id, target, url, rationale, relationship="maps_to"):
    if type_id in types and target in entries and not entries[target].get("deprecated"):
        mappings[(type_id, relationship, target)] = dict(source=type_id, target=target, type=relationship, source_url=url, rationale=rationale)


# Keep friendly IDs stable; every other weakness has a stable cwe_<number> ID.
preferred = {
    "89":"sql_injection","78":"command_injection","79":"cross_site_scripting","918":"ssrf",
    "22":"path_traversal","862":"missing_authorization","639":"idor","287":"authentication_bypass",
    "502":"insecure_deserialization","200":"sensitive_data_exposure","1427":"prompt_injection",
    "1021":"clickjacking","352":"csrf","611":"xml_external_entity","601":"open_redirect",
    "444":"http_request_smuggling","113":"http_response_splitting","770":"unbounded_resource_consumption",
    "799":"missing_rate_limiting","400":"resource_exhaustion","345":"data_authenticity_failure",
    "798":"hardcoded_credentials","327":"weak_cryptography","295":"improper_certificate_validation",
    "362":"race_condition","120":"buffer_overflow","125":"out_of_bounds_read","787":"out_of_bounds_write",
    "416":"use_after_free","190":"integer_overflow","1395":"vulnerable_dependency",
    "1104":"unmaintained_dependency","1426":"unsafe_model_output_handling","74":"injection",
    "732":"incorrect_permissions","269":"improper_privilege_management","306":"missing_authentication",
    "384":"session_fixation","613":"insufficient_session_expiration","209":"verbose_error_disclosure",
    "532":"sensitive_data_in_logs","614":"insecure_cookie_transport","1004":"missing_httponly_cookie",
    "915":"mass_assignment","942":"permissive_cors","346":"origin_validation_failure",
    "841":"business_logic_workflow_failure","434":"unrestricted_file_upload",
    "1333":"regular_expression_denial_of_service","319":"cleartext_sensitive_transport",
    "311":"missing_sensitive_data_encryption","208":"timing_side_channel","117":"log_injection",
    "1236":"csv_formula_injection","94":"code_injection","1336":"template_injection",
    "347":"improper_signature_verification",
}
aliases = {
    "clickjacking":["UI redressing","frame embedding","anti-framing headers"],
    "unbounded_resource_consumption":["unbounded consumption","cost abuse","missing resource quotas"],
    "missing_rate_limiting":["rate limiting","throttling","spam","subscription abuse"],
    "data_authenticity_failure":["content spoofing","brand impersonation"],
}
archive = zipfile.ZipFile(io.BytesIO(fetch("cwe-5.0", "https://cwe.mitre.org/data/xml/cwec_v5.0.xml.zip")))
root = ET.fromstring(archive.read(next(name for name in archive.namelist() if name.endswith(".xml"))))
ns = {"c": "http://cwe.mitre.org/cwe-8"}
assert root.get("Version") == "5.0"
weaknesses = list(root.find("c:Weaknesses", ns))
assert len(weaknesses) == 984
framework("cwe","MITRE CWE","5.0","https://cwe.mitre.org/data/downloads.html","weakness_taxonomy",
          "All 984 published weaknesses. Deprecated entries and grouping pillars remain reference records; deprecated choices cannot be assigned.",
          "https://cwe.mitre.org/about/termsofuse.html")
legacy_ids = {old["id"] for old in v1["types"]}
for old in v1["types"]:
    types[old["id"]] = old.copy()
for w in weaknesses:
    number = w.get("ID")
    id = preferred.get(number, "cwe_" + number)
    deprecated = w.get("Status") == "Deprecated"
    description = plain(" ".join(w.find("c:Description", ns).itertext()))
    alternatives = [plain(" ".join(term.itertext())) for term in w.findall("c:Alternate_Terms/c:Alternate_Term/c:Term", ns)]
    if id not in types:
        types[id] = dict(id=id,name=w.get("Name"),description=description,aliases=alternatives,parents=[],
                         classifiable=not deprecated and w.get("Abstraction")!="Pillar",deprecated=deprecated)
    types[id].update(cwe_id="CWE-"+number,source_url="https://cwe.mitre.org/data/definitions/"+number+".html",
                     mapping_guidance=w.findtext("c:Mapping_Notes/c:Usage",default="",namespaces=ns))
    types[id]["aliases"] = sorted(set(types[id]["aliases"] + aliases.get(id,[]) + ["CWE-"+number]))
    entry("cwe","CWE-"+number,w.get("Name"),"weakness",types[id]["source_url"],description,deprecated)
for w in weaknesses:
    id = preferred.get(w.get("ID"),"cwe_"+w.get("ID"))
    if id in legacy_ids:
        continue
    parents = []
    for rel in w.findall("c:Related_Weaknesses/c:Related_Weakness",ns):
        if rel.get("Nature")=="ChildOf" and rel.get("View_ID")=="1000":
            parent = preferred.get(rel.get("CWE_ID"),"cwe_"+rel.get("CWE_ID"))
            if parent in types and parent!=id:
                parents.append(parent)
    types[id]["parents"] = sorted(set(parents))
for id,t in types.items():
    if t.get("cwe_id"):
        mapping(id,"cwe:"+t["cwe_id"],t["source_url"],"Identifies this published CWE weakness. Prefer a specific root cause and review upstream mapping guidance.")

custom = [
    ("security_misconfiguration","Security misconfiguration","An observed configuration defeats an intended security control. A hardening recommendation without an affected security boundary is not sufficient.",["unsafe defaults","missing security headers"],"https://top10.owasp.org/2025/A02_2025-Security_Misconfiguration/"),
    ("dangling_dns_record","Dangling DNS or deprovisioned service reference","DNS references a deprovisioned or unavailable external service. Establish impact separately: a dangling record does not by itself demonstrate takeover.",["stale CNAME","orphaned DNS","stale service inventory"],"https://api-security.owasp.org/editions/2023/en/0xa9-improper-inventory-management/"),
    ("subdomain_takeover","Subdomain takeover","An attacker can claim the external resource referenced by an organization's DNS and serve content under its hostname. Requires demonstrated claimability or equivalent proof.",["dangling DNS takeover"],"https://api-security.owasp.org/editions/2023/en/0xa9-improper-inventory-management/"),
    ("consent_enforcement_failure","Consent enforcement failure","An operation requires a subject's consent but proceeds without a valid grant. A deliberately public interface is not automatically an authorization vulnerability.",["subscription consent","opt-in failure","unsolicited enrollment"],"https://api-security.owasp.org/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/"),
    ("system_prompt_exposure","Hidden instruction or system prompt exposure","Protected system instructions or hidden context cross an intended confidentiality boundary. Public prompt templates alone do not establish impact.",["system prompt leakage","hidden context exposure"],"https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/9253e38ade58e959b531c0c5c9a4842272c9cd0e/2026/final/LLM08_HiddenContextExposure.md"),
    ("model_or_data_poisoning","Model or training data poisoning","Attacker-controlled model artifacts or training data change model behavior across an intended integrity boundary.",["model poisoning","training data poisoning"],"https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/9253e38ade58e959b531c0c5c9a4842272c9cd0e/2026/final/LLM05_DataModelPoisoning.md"),
    ("retrieval_or_memory_poisoning","Retrieval, vector or agent memory poisoning","Attacker-controlled retrieval, embeddings or persistent agent memory alter trusted context or future actions across an intended boundary.",["RAG poisoning","vector poisoning","memory poisoning"],"https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/9253e38ade58e959b531c0c5c9a4842272c9cd0e/2026/final/LLM09_VectorAndEmbeddingWeaknesses.md"),
    ("unsafe_model_reliance","Unsafe reliance on model output","Unverified model-generated claims drive security-sensitive or consequential decisions without required validation.",["misinformation","overreliance"],"https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/9253e38ade58e959b531c0c5c9a4842272c9cd0e/2026/final/LLM07_Misinformation.md"),
]
for id,name,description,alternate,url in custom:
    types[id]=dict(id=id,name=name,description=description,aliases=alternate,parents=[],classifiable=True,deprecated=False,source_url=url)

web_names=["Broken_Access_Control","Security_Misconfiguration","Software_Supply_Chain_Failures","Cryptographic_Failures","Injection","Insecure_Design","Authentication_Failures","Software_or_Data_Integrity_Failures","Security_Logging_and_Alerting_Failures","Mishandling_of_Exceptional_Conditions"]
framework("owasp-web","OWASP Top 10","2025","https://top10.owasp.org/2025/","risk_taxonomy","All 10 categories and publisher-listed CWE cross-references.","https://creativecommons.org/licenses/by-sa/4.0/")
for i,name in enumerate(web_names,1):
    external="A"+str(i).zfill(2)
    path=external+"_2025-"+name
    source="https://raw.githubusercontent.com/OWASP/Top10/3a31f35346c3f4e90f350395124382fa53af2afe/2025/docs/en/"+path+".md"
    text=fetch("owasp-web-"+external,source).decode()
    target=entry("owasp-web",external,name.replace("_"," "),"risk","https://top10.owasp.org/2025/"+path+"/")
    section=re.split(r"(?im)^##\s+List of Mapped CWEs",text)
    for number in sorted(set(re.findall(r"CWE-(\d+)",section[-1] if len(section)>1 else ""))):
        mapping(preferred.get(number,"cwe_"+number),target,source,"Listed in the publisher's mapped-CWE table. Relevance is not equivalence or proof of compliance.")
api_names=["broken-object-level-authorization","broken-authentication","broken-object-property-level-authorization","unrestricted-resource-consumption","broken-function-level-authorization","unrestricted-access-to-sensitive-business-flows","server-side-request-forgery","security-misconfiguration","improper-inventory-management","unsafe-consumption-of-apis"]
framework("owasp-api","OWASP API Security Top 10","2023","https://api-security.owasp.org/editions/2023/en/0x00-header/","risk_taxonomy","All 10 published API risk categories.","https://creativecommons.org/licenses/by-sa/4.0/")
for i,name in enumerate(api_names,1):
    path="0x"+format(160+i,"x")+"-"+name
    source="https://raw.githubusercontent.com/OWASP/API-Security/33cea37b2ffde3e2e62f6b5d79a029a22a846633/editions/2023/en/"+path+".md"
    fetch("owasp-api-"+str(i),source)
    entry("owasp-api","API"+str(i),name.replace("-"," ").capitalize(),"risk","https://api-security.owasp.org/editions/2023/en/"+path+"/")
llm_names=["PromptInjection","SensitiveInformationDisclosure","ExcessiveAgency","SupplyChain","DataModelPoisoning","UnboundedConsumption","Misinformation","HiddenContextExposure","VectorAndEmbeddingWeaknesses","ImproperOutputHandling"]
llm_titles=["Prompt Injection","Sensitive Information Disclosure","Excessive Agency","Supply Chain","Data and Model Poisoning","Unbounded Consumption","Misinformation","Hidden Context Exposure","Vector and Embedding Weaknesses","Improper Output Handling"]
framework("owasp-llm","OWASP GenAI LLM Top 10","2026","https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/tree/9253e38ade58e959b531c0c5c9a4842272c9cd0e/2026/final","risk_taxonomy","All 10 categories in the 2026 edition. Catalog v1 retains the different 2025 numbering.","https://creativecommons.org/licenses/by-sa/4.0/")
for i,(name,title) in enumerate(zip(llm_names,llm_titles),1):
    filename="LLM"+str(i).zfill(2)+"_"+name+".md"
    url="https://raw.githubusercontent.com/GenAI-Security-Project/GenAI-LLM-Top10/9253e38ade58e959b531c0c5c9a4842272c9cd0e/2026/final/"+filename
    fetch("owasp-llm-"+str(i),url)
    entry("owasp-llm","LLM"+str(i).zfill(2),title,"risk",url)

# Public OSCAL indexes retain groups, controls and nested enhancements.
nist_commit="f0de6d8d8c059d374f15e0ae07508d82e370fc1d"
nist=[
    ("nist-csf","NIST Cybersecurity Framework","2.0","CSF/v2.0/json/NIST_CSF_v2.0_catalog.json"),
    ("nist-ai-rmf","NIST AI Risk Management Framework","1.0","AI100-1/ver1/json/NIST_AI-RMF_v1_catalog.json"),
    ("nist-800-53","NIST SP 800-53","5.2.0","SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"),
    ("nist-800-171","NIST SP 800-171","Revision 3","SP800-171/rev3/json/NIST_SP800-171_rev3_catalog.json"),
    ("nist-ssdf","NIST Secure Software Development Framework","1.1","SP800-218/ver1/json/NIST_SP800-218_ver1_catalog.json"),
]
for id,name,release,path in nist:
    url="https://raw.githubusercontent.com/usnistgov/oscal-content/"+nist_commit+"/nist.gov/"+path
    content=json.loads(fetch(id,url))["catalog"]
    framework(id,name,release,url,"control_framework","Complete publisher OSCAL index, including groups and nested controls/enhancements. Withdrawn entries are marked deprecated. Discovery summaries are not complete control text.","https://www.nist.gov/open/license")
    def walk(nodes,parent=None):
        for node in nodes:
            if id=="nist-800-53":
                labels=[p["value"] for p in node.get("props",[]) if p["name"]=="label" and not p.get("class")]
                external=labels[0] if labels else node["id"].upper()
            elif id=="nist-800-171":
                external=node["id"].removeprefix("SP_800_171_")
            elif id=="nist-ai-rmf":
                external=node["id"].replace("_"," ")
            else:
                external=node["id"]
            prose=" ".join(part.get("prose","") for part in node.get("parts",[]) if part.get("name") in ["overview","statement"])
            title=node.get("title",external)
            if title in [node["id"],external]:
                title=plain(prose)[:180] or title
            deprecated=any(p["name"]=="status" and p["value"] in ["withdrawn","deprecated"] for p in node.get("props",[]))
            target=entry(id,external,title,node.get("class","control"),url+"#"+node["id"],prose,deprecated,[parent] if parent else None)
            walk(node.get("controls",[])+node.get("groups",[]),target)
    walk(content.get("groups",[])+content.get("controls",[]))
asvs_url="https://raw.githubusercontent.com/OWASP/ASVS/180622b1329ee7ed349c9f5ce5e14fa91f42c359/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.json"
asvs=json.loads(fetch("owasp-asvs",asvs_url))
framework("owasp-asvs","OWASP Application Security Verification Standard","5.0.0",asvs_url,"verification_standard","Complete published verification requirement index.","https://creativecommons.org/licenses/by-sa/4.0/")
for chapter in asvs["Requirements"]:
    for section in chapter["Items"]:
        for requirement in section["Items"]:
            external=requirement["Shortcode"].removeprefix("v5.0.0-")
            entry("owasp-asvs",external,requirement["Description"],"verification_requirement",asvs_url+"#"+external,section["Name"])
atlas_url="https://raw.githubusercontent.com/mitre-atlas/atlas-data/f56c1468731d6428e5bf875263b4643b46d67437/dist/v6/ATLAS-2026.10.yaml"
atlas=yaml.safe_load(fetch("mitre-atlas",atlas_url))
framework("mitre-atlas","MITRE ATLAS",atlas["collection"]["version"],atlas_url,"threat_knowledge_base","Complete tactics, techniques/subtechniques and mitigation index; case studies, software and entities are not choices.","https://github.com/mitre-atlas/atlas-data/blob/f56c1468731d6428e5bf875263b4643b46d67437/LICENSE")
for key,kind in [("tactics","tactic"),("techniques","technique"),("mitigations","mitigation")]:
    for item in atlas[key].values():
        entry("mitre-atlas",item["id"],item["name"],kind,"https://atlas.mitre.org/"+key+"/"+item["id"],item.get("description",""),item.get("deprecated",False))

# Brief editorial index labels, never copied licensed control text.
aiuc_index=fetch("aiuc-index","https://standard.aiuc-1.com/llms.txt").decode()
aiuc_labels={
    "A001":"Input usage rules","A002":"Output usage rules","A003":"Data access boundaries","A004":"Confidential intellectual assets","A005":"Customer data isolation","A006":"Personal data safeguards","A007":"Intellectual property safeguards","A008":"Credential confidentiality","A009":"Independent privacy testing",
    "B001":"Independent security evaluation","B002":"Adversarial input recognition","B003":"Controlled technical disclosure","B004":"Endpoint extraction resistance","B005":"Live input inspection","B006":"Agent action authorization","B007":"User privilege enforcement","B008":"Deployment infrastructure protection","B009":"Output disclosure boundaries","B010":"Secure code generation",
    "C001":"Risk classification model","C002":"Release readiness testing","C003":"Harm prevention","C004":"Output scope boundaries","C005":"Agent hazard safeguards","C006":"Output security safeguards","C007":"Human escalation","C008":"Continuous risk observation","C009":"Feedback and intervention","C010":"Independent safety testing",
    "D001":"Factual output reliability","D003":"Tool invocation boundaries","D004":"Independent reliability testing",
    "E001":"Security incident preparation","E002":"Harm incident preparation","E003":"Factual failure preparation","E004":"Accountable ownership","E005":"Storage security documentation","E006":"Supplier due diligence","E008":"Process assurance reviews","E009":"Supplier access oversight","E010":"Acceptable use rules","E011":"Processing geography records","E012":"Regulatory obligations register","E013":"Quality assurance system","E015":"Agent activity records","E016":"AI interaction disclosure","E017":"Transparency commitments","E018":"Independent accountability testing",
    "F001":"Cyber misuse safeguards","F002":"Catastrophic misuse safeguards"
}
aiuc_rows=re.findall(r"\[([A-F][0-9]{3}): ([^\]]+)\]\(([^)]+)\)",aiuc_index)
assert {row[0] for row in aiuc_rows}==set(aiuc_labels)
framework("aiuc-1","AIUC-1","2026-10-15","https://standard.aiuc-1.com/changelog","control_framework","All 50 public requirement identifiers with abbreviated editorial labels and official links; licensed control text and evidence guidance are not redistributed.","https://standard.aiuc-1.com/legal/terms")
for external,_,url in aiuc_rows:
    entry("aiuc-1",external,aiuc_labels[external],"requirement_reference",url.removesuffix(".md"))
framework("iso27001","ISO/IEC 27001","2022","https://www.iso.org/standard/27001","control_framework","Framework reference only. Licensed Annex A control content is not bundled.","https://www.iso.org/copyright.html")
entry("iso27001","ISO-IEC-27001:2022","Information security management system","framework_reference","https://www.iso.org/standard/27001")
framework("soc2","AICPA Trust Services Criteria (SOC 2)","2017; revised points of focus 2022","https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022","assurance_criteria","All five public trust-service categories. Detailed licensed criteria and points of focus are not bundled.","https://www.aicpa-cima.com/help/terms-and-conditions")
for external,name in [("security","Security"),("availability","Availability"),("processing-integrity","Processing integrity"),("confidentiality","Confidentiality"),("privacy","Privacy")]:
    entry("soc2",external,name,"trust_category","https://www.aicpa-cima.com/resources/landing/trust-services-criteria")
framework("pci-dss","PCI Data Security Standard","4.0.1","https://www.pcisecuritystandards.org/standards/pci-dss/","control_framework","All 12 top-level requirement areas with editorial labels. Detailed subrequirements, testing procedures and licensed text are not bundled.","https://www.pcisecuritystandards.org/terms-and-conditions/")
for i,name in enumerate(["Network safeguards","Secure configuration","Stored account data","Transmitted account data","Malware defenses","Secure software","Business access boundaries","Identity verification","Physical access","Activity records","Security evaluation","Security governance"],1):
    entry("pci-dss",str(i),name,"requirement_area","https://www.pcisecuritystandards.org/standards/pci-dss/")

# Relevance links supplement publisher mappings; they do not select compliance.
links={
    "clickjacking":["owasp-web:A02"],
    "security_misconfiguration":["owasp-web:A02","owasp-api:API8"],
    "dangling_dns_record":["owasp-web:A02","owasp-api:API9"],
    "subdomain_takeover":["owasp-web:A02","owasp-api:API9"],
    "missing_rate_limiting":["owasp-api:API4","owasp-api:API6"],
    "unbounded_resource_consumption":["owasp-api:API4","owasp-llm:LLM06"],
    "resource_exhaustion":["owasp-api:API4"],
    "consent_enforcement_failure":["owasp-api:API6"],
    "data_authenticity_failure":["owasp-web:A08"],
    "prompt_injection":["owasp-llm:LLM01","aiuc-1:B002"],
    "indirect_prompt_injection":["owasp-llm:LLM01","aiuc-1:B002"],
    "excessive_agency":["owasp-llm:LLM03","aiuc-1:B006"],
    "unsafe_tool_use":["owasp-llm:LLM03","aiuc-1:D003"],
    "sensitive_data_exposure":["owasp-llm:LLM02","aiuc-1:A008"],
    "vulnerable_dependency":["owasp-web:A03","owasp-llm:LLM04"],
    "model_or_data_poisoning":["owasp-llm:LLM05"],
    "unsafe_model_output_handling":["owasp-llm:LLM10"],
    "system_prompt_exposure":["owasp-llm:LLM08"],
    "retrieval_or_memory_poisoning":["owasp-llm:LLM09"],
    "unsafe_model_reliance":["owasp-llm:LLM07"],
}
for type_id,targets in links.items():
    for target in targets:
        mapping(type_id,target,entries[target]["source_url"],"Editorial relevance reference: apply only when observed boundaries and framework scope match. Not equivalence, certification or an automatic selection.","addressed_by" if target.startswith("aiuc-1:") else "maps_to")
for old in v1["mappings"]:
    if not old["target"].startswith("owasp-llm:"):
        mapping(old["source"],old["target"],old["source_url"],old["rationale"],old["type"])
catalog["types"]=sorted(types.values(),key=lambda x:x["id"])
catalog["entries"]=sorted(entries.values(),key=lambda x:x["id"])
catalog["mappings"]=sorted(mappings.values(),key=lambda x:(x["source"],x["type"],x["target"]))
catalog["frameworks"].sort(key=lambda x:x["id"])
counts=collections.Counter(e["framework"] for e in catalog["entries"])
for f in catalog["frameworks"]:
    f["entry_count"]=counts[f["id"]]


def output(path,value):
    text=json.dumps(value,indent=2,ensure_ascii=False)+"\n"
    if args.check:
        if not path.exists() or path.read_text()!=text:
            raise ValueError("Generated file differs: "+str(path))
    else:
        path.write_text(text)


output(ROOT/"pkg/catalog/v2.json",catalog)
output(lock_path,dict(sorted(sources.items())))
inventory=[
    "# Security Graph catalog v2 inventory","",
    "Generated from scripts/generate-catalog.py. This is a finite, versioned inventory, not a claim to enumerate every possible issue or every standard in existence.",
    "Mappings express relevance only. Coverage levels below are explicit; references and categories are not complete requirements or certification results.","",
    "## Framework coverage","","| ID | Framework | Release | Entries | Scope |","| --- | --- | --- | ---: | --- |"
]
for f in catalog["frameworks"]:
    inventory.append("| "+" | ".join([f["id"],"["+f["name"]+"]("+f["source_url"]+")",f["release"],str(f["entry_count"]),f["coverage"]])+" |")
inventory.extend(["","## Vulnerability types","","| ID | Name | Selectable | Source |","| --- | --- | --- | --- |"])
for t in catalog["types"]:
    inventory.append("| "+" | ".join([t["id"],t["name"].replace("|","/"),"yes" if t["classifiable"] and not t["deprecated"] else "no",t.get("source_url","Editorial definition; see v1 provenance")])+" |")
for f in catalog["frameworks"]:
    inventory.extend(["","## "+f["name"],"","| ID | Name | Kind |","| --- | --- | --- |"])
    for e in catalog["entries"]:
        if e["framework"]==f["id"]:
            inventory.append("| "+" | ".join([e["id"],e["name"].replace("|","/").replace("\n"," "),e["kind"]+(" (deprecated)" if e.get("deprecated") else "")])+" |")
text="\n".join(inventory)+"\n"
path=ROOT/"docs/catalog-v2-inventory.md"
if args.check:
    assert path.read_text()==text
else:
    path.write_text(text)
print(json.dumps({"types":len(types),"selectable_types":sum(t["classifiable"] and not t["deprecated"] for t in types.values()),"entries":len(entries),"frameworks":len(catalog["frameworks"]),"mappings":len(mappings),"entries_by_framework":counts},indent=2))
