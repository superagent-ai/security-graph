# Security Graph catalog v2 inventory

Generated from scripts/generate-catalog.py. This is a finite, versioned inventory, not a claim to enumerate every possible issue or every standard in existence.
Mappings express relevance only. Coverage levels below are explicit; references and categories are not complete requirements or certification results.

## Framework coverage

| ID | Framework | Release | Entries | Scope |
| --- | --- | --- | ---: | --- |
| aiuc-1 | [AIUC-1](https://standard.aiuc-1.com/changelog) | 2026-10-15 | 50 | All 50 public requirement identifiers with abbreviated editorial labels and official links; licensed control text and evidence guidance are not redistributed. |
| cwe | [MITRE CWE](https://cwe.mitre.org/data/downloads.html) | 5.0 | 984 | All 984 published weaknesses. Deprecated entries and grouping pillars remain reference records; deprecated choices cannot be assigned. |
| iso27001 | [ISO/IEC 27001](https://www.iso.org/standard/27001) | 2022 | 1 | Framework reference only. Licensed Annex A control content is not bundled. |
| mitre-atlas | [MITRE ATLAS](https://raw.githubusercontent.com/mitre-atlas/atlas-data/f56c1468731d6428e5bf875263b4643b46d67437/dist/v6/ATLAS-2026.10.yaml) | 2026.10 | 281 | Complete tactics, techniques/subtechniques and mitigation index; case studies, software and entities are not choices. |
| nist-800-171 | [NIST SP 800-171](https://raw.githubusercontent.com/usnistgov/oscal-content/f0de6d8d8c059d374f15e0ae07508d82e370fc1d/nist.gov/SP800-171/rev3/json/NIST_SP800-171_rev3_catalog.json) | Revision 3 | 147 | Complete publisher OSCAL index, including groups and nested controls/enhancements. Withdrawn entries are marked deprecated. Discovery summaries are not complete control text. |
| nist-800-53 | [NIST SP 800-53](https://raw.githubusercontent.com/usnistgov/oscal-content/f0de6d8d8c059d374f15e0ae07508d82e370fc1d/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json) | 5.2.0 | 1216 | Complete publisher OSCAL index, including groups and nested controls/enhancements. Withdrawn entries are marked deprecated. Discovery summaries are not complete control text. |
| nist-ai-rmf | [NIST AI Risk Management Framework](https://raw.githubusercontent.com/usnistgov/oscal-content/f0de6d8d8c059d374f15e0ae07508d82e370fc1d/nist.gov/AI100-1/ver1/json/NIST_AI-RMF_v1_catalog.json) | 1.0 | 95 | Complete publisher OSCAL index, including groups and nested controls/enhancements. Withdrawn entries are marked deprecated. Discovery summaries are not complete control text. |
| nist-csf | [NIST Cybersecurity Framework](https://raw.githubusercontent.com/usnistgov/oscal-content/f0de6d8d8c059d374f15e0ae07508d82e370fc1d/nist.gov/CSF/v2.0/json/NIST_CSF_v2.0_catalog.json) | 2.0 | 225 | Complete publisher OSCAL index, including groups and nested controls/enhancements. Withdrawn entries are marked deprecated. Discovery summaries are not complete control text. |
| nist-ssdf | [NIST Secure Software Development Framework](https://raw.githubusercontent.com/usnistgov/oscal-content/f0de6d8d8c059d374f15e0ae07508d82e370fc1d/nist.gov/SP800-218/ver1/json/NIST_SP800-218_ver1_catalog.json) | 1.1 | 65 | Complete publisher OSCAL index, including groups and nested controls/enhancements. Withdrawn entries are marked deprecated. Discovery summaries are not complete control text. |
| owasp-api | [OWASP API Security Top 10](https://api-security.owasp.org/editions/2023/en/0x00-header/) | 2023 | 10 | All 10 published API risk categories. |
| owasp-asvs | [OWASP Application Security Verification Standard](https://raw.githubusercontent.com/OWASP/ASVS/180622b1329ee7ed349c9f5ce5e14fa91f42c359/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.json) | 5.0.0 | 345 | Complete published verification requirement index. |
| owasp-llm | [OWASP GenAI LLM Top 10](https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/tree/9253e38ade58e959b531c0c5c9a4842272c9cd0e/2026/final) | 2026 | 10 | All 10 categories in the 2026 edition. Catalog v1 retains the different 2025 numbering. |
| owasp-web | [OWASP Top 10](https://top10.owasp.org/2025/) | 2025 | 10 | All 10 categories and publisher-listed CWE cross-references. |
| pci-dss | [PCI Data Security Standard](https://www.pcisecuritystandards.org/standards/pci-dss/) | 4.0.1 | 12 | All 12 top-level requirement areas with editorial labels. Detailed subrequirements, testing procedures and licensed text are not bundled. |
| soc2 | [AICPA Trust Services Criteria (SOC 2)](https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022) | 2017; revised points of focus 2022 | 5 | All five public trust-service categories. Detailed licensed criteria and points of focus are not bundled. |

## Vulnerability types

| ID | Name | Selectable | Source |
| --- | --- | --- | --- |
| authentication_bypass | Authentication bypass | yes | https://cwe.mitre.org/data/definitions/287.html |
| blind_sql_injection | Blind SQL injection | yes | Editorial definition; see v1 provenance |
| buffer_overflow | Buffer Copy without Checking Size of Input | yes | https://cwe.mitre.org/data/definitions/120.html |
| business_logic_workflow_failure | Improper Enforcement of Behavioral Workflow | yes | https://cwe.mitre.org/data/definitions/841.html |
| cleartext_sensitive_transport | Cleartext Transmission of Sensitive Information | yes | https://cwe.mitre.org/data/definitions/319.html |
| clickjacking | Improper Restriction of Rendered UI Layers or Frames | yes | https://cwe.mitre.org/data/definitions/1021.html |
| code_injection | Improper Control of Generation of Code | yes | https://cwe.mitre.org/data/definitions/94.html |
| command_injection | OS command injection | yes | https://cwe.mitre.org/data/definitions/78.html |
| consent_enforcement_failure | Consent enforcement failure | yes | https://api-security.owasp.org/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/ |
| cross_site_scripting | Cross-site scripting | yes | https://cwe.mitre.org/data/definitions/79.html |
| csrf | Cross-Site Request Forgery | yes | https://cwe.mitre.org/data/definitions/352.html |
| csv_formula_injection | Improper Neutralization of Formula Elements in a CSV File | yes | https://cwe.mitre.org/data/definitions/1236.html |
| cwe_1007 | Insufficient Visual Distinction of Homoglyphs Presented to User | yes | https://cwe.mitre.org/data/definitions/1007.html |
| cwe_102 | Struts: Duplicate Validation Forms | yes | https://cwe.mitre.org/data/definitions/102.html |
| cwe_1022 | Use of Web Link to Untrusted Target with window.opener Access | yes | https://cwe.mitre.org/data/definitions/1022.html |
| cwe_1023 | Incomplete Comparison with Missing Factors | yes | https://cwe.mitre.org/data/definitions/1023.html |
| cwe_1024 | Comparison of Incompatible Types | yes | https://cwe.mitre.org/data/definitions/1024.html |
| cwe_1025 | Comparison Using Wrong Factors | yes | https://cwe.mitre.org/data/definitions/1025.html |
| cwe_103 | Struts: Incomplete validate() Method Definition | yes | https://cwe.mitre.org/data/definitions/103.html |
| cwe_1037 | Processor Optimization Removal or Modification of Security-critical Code | yes | https://cwe.mitre.org/data/definitions/1037.html |
| cwe_1038 | Insecure Automated Optimizations | yes | https://cwe.mitre.org/data/definitions/1038.html |
| cwe_1039 | Inadequate Detection or Handling of Adversarial Input Perturbations in Automated Recognition Mechanism | yes | https://cwe.mitre.org/data/definitions/1039.html |
| cwe_104 | Struts: Form Bean Does Not Extend Validation Class | yes | https://cwe.mitre.org/data/definitions/104.html |
| cwe_1041 | Use of Redundant Code | yes | https://cwe.mitre.org/data/definitions/1041.html |
| cwe_1042 | Static Member Data Element outside of a Singleton Class Element | yes | https://cwe.mitre.org/data/definitions/1042.html |
| cwe_1043 | Data Element Aggregating an Excessively Large Number of Non-Primitive Elements | yes | https://cwe.mitre.org/data/definitions/1043.html |
| cwe_1044 | Architecture with Number of Horizontal Layers Outside of Expected Range | yes | https://cwe.mitre.org/data/definitions/1044.html |
| cwe_1045 | Parent Class with a Virtual Destructor and a Child Class without a Virtual Destructor | yes | https://cwe.mitre.org/data/definitions/1045.html |
| cwe_1046 | Creation of Immutable Text Using String Concatenation | yes | https://cwe.mitre.org/data/definitions/1046.html |
| cwe_1047 | Modules with Circular Dependencies | yes | https://cwe.mitre.org/data/definitions/1047.html |
| cwe_1048 | Invokable Control Element with Large Number of Outward Calls | yes | https://cwe.mitre.org/data/definitions/1048.html |
| cwe_1049 | Excessive Data Query Operations in a Large Data Table | yes | https://cwe.mitre.org/data/definitions/1049.html |
| cwe_105 | Struts: Form Field Without Validator | yes | https://cwe.mitre.org/data/definitions/105.html |
| cwe_1050 | Excessive Platform Resource Consumption within a Loop | yes | https://cwe.mitre.org/data/definitions/1050.html |
| cwe_1051 | Initialization with Hard-Coded Network Resource Configuration Data | yes | https://cwe.mitre.org/data/definitions/1051.html |
| cwe_1052 | Excessive Use of Hard-Coded Literals in Initialization | yes | https://cwe.mitre.org/data/definitions/1052.html |
| cwe_1053 | Missing Documentation for Design | yes | https://cwe.mitre.org/data/definitions/1053.html |
| cwe_1054 | Invocation of a Control Element at an Unnecessarily Deep Horizontal Layer | yes | https://cwe.mitre.org/data/definitions/1054.html |
| cwe_1055 | Multiple Inheritance from Concrete Classes | yes | https://cwe.mitre.org/data/definitions/1055.html |
| cwe_1056 | Invokable Control Element with Variadic Parameters | yes | https://cwe.mitre.org/data/definitions/1056.html |
| cwe_1057 | Data Access Operations Outside of Expected Data Manager Component | yes | https://cwe.mitre.org/data/definitions/1057.html |
| cwe_1058 | Invokable Control Element in Multi-Thread Context with non-Final Static Storable or Member Element | yes | https://cwe.mitre.org/data/definitions/1058.html |
| cwe_1059 | Insufficient Technical Documentation | yes | https://cwe.mitre.org/data/definitions/1059.html |
| cwe_106 | Struts: Plug-in Framework not in Use | yes | https://cwe.mitre.org/data/definitions/106.html |
| cwe_1060 | Excessive Number of Inefficient Server-Side Data Accesses | yes | https://cwe.mitre.org/data/definitions/1060.html |
| cwe_1061 | Insufficient Encapsulation | yes | https://cwe.mitre.org/data/definitions/1061.html |
| cwe_1062 | Parent Class with References to Child Class | yes | https://cwe.mitre.org/data/definitions/1062.html |
| cwe_1063 | Creation of Class Instance within a Static Code Block | yes | https://cwe.mitre.org/data/definitions/1063.html |
| cwe_1064 | Invokable Control Element with Signature Containing an Excessive Number of Parameters | yes | https://cwe.mitre.org/data/definitions/1064.html |
| cwe_1065 | Runtime Resource Management Control Element in a Component Built to Run on Application Servers | yes | https://cwe.mitre.org/data/definitions/1065.html |
| cwe_1066 | Missing Serialization Control Element | yes | https://cwe.mitre.org/data/definitions/1066.html |
| cwe_1067 | Excessive Execution of Sequential Searches of Data Resource | yes | https://cwe.mitre.org/data/definitions/1067.html |
| cwe_1068 | Inconsistency Between Implementation and Documented Design | yes | https://cwe.mitre.org/data/definitions/1068.html |
| cwe_1069 | Empty Exception Block | yes | https://cwe.mitre.org/data/definitions/1069.html |
| cwe_107 | Struts: Unused Validation Form | yes | https://cwe.mitre.org/data/definitions/107.html |
| cwe_1070 | Serializable Data Element Containing non-Serializable Item Elements | yes | https://cwe.mitre.org/data/definitions/1070.html |
| cwe_1071 | Empty Code Block | yes | https://cwe.mitre.org/data/definitions/1071.html |
| cwe_1072 | Data Resource Access without Use of Connection Pooling | yes | https://cwe.mitre.org/data/definitions/1072.html |
| cwe_1073 | Non-SQL Invokable Control Element with Excessive Number of Data Resource Accesses | yes | https://cwe.mitre.org/data/definitions/1073.html |
| cwe_1074 | Class with Excessively Deep Inheritance | yes | https://cwe.mitre.org/data/definitions/1074.html |
| cwe_1075 | Unconditional Control Flow Transfer outside of Switch Block | yes | https://cwe.mitre.org/data/definitions/1075.html |
| cwe_1076 | Insufficient Adherence to Expected Conventions | yes | https://cwe.mitre.org/data/definitions/1076.html |
| cwe_1077 | Floating Point Comparison with Incorrect Operator | yes | https://cwe.mitre.org/data/definitions/1077.html |
| cwe_1078 | Inappropriate Source Code Style or Formatting | yes | https://cwe.mitre.org/data/definitions/1078.html |
| cwe_1079 | Parent Class without Virtual Destructor Method | yes | https://cwe.mitre.org/data/definitions/1079.html |
| cwe_108 | Struts: Unvalidated Action Form | yes | https://cwe.mitre.org/data/definitions/108.html |
| cwe_1080 | Source Code File with Excessive Number of Lines of Code | yes | https://cwe.mitre.org/data/definitions/1080.html |
| cwe_1082 | Class Instance Self Destruction Control Element | yes | https://cwe.mitre.org/data/definitions/1082.html |
| cwe_1083 | Data Access from Outside Expected Data Manager Component | yes | https://cwe.mitre.org/data/definitions/1083.html |
| cwe_1084 | Invokable Control Element with Excessive File or Data Access Operations | yes | https://cwe.mitre.org/data/definitions/1084.html |
| cwe_1085 | Invokable Control Element with Excessive Volume of Commented-out Code | yes | https://cwe.mitre.org/data/definitions/1085.html |
| cwe_1086 | Class with Excessive Number of Child Classes | yes | https://cwe.mitre.org/data/definitions/1086.html |
| cwe_1087 | Class with Virtual Method without a Virtual Destructor | yes | https://cwe.mitre.org/data/definitions/1087.html |
| cwe_1088 | Synchronous Access of Remote Resource without Timeout | yes | https://cwe.mitre.org/data/definitions/1088.html |
| cwe_1089 | Large Data Table with Excessive Number of Indices | yes | https://cwe.mitre.org/data/definitions/1089.html |
| cwe_109 | Struts: Validator Turned Off | yes | https://cwe.mitre.org/data/definitions/109.html |
| cwe_1090 | Method Containing Access of a Member Element from Another Class | yes | https://cwe.mitre.org/data/definitions/1090.html |
| cwe_1091 | Use of Object without Invoking Destructor Method | yes | https://cwe.mitre.org/data/definitions/1091.html |
| cwe_1092 | Use of Same Invokable Control Element in Multiple Architectural Layers | yes | https://cwe.mitre.org/data/definitions/1092.html |
| cwe_1093 | Excessively Complex Data Representation | yes | https://cwe.mitre.org/data/definitions/1093.html |
| cwe_1094 | Excessive Index Range Scan for a Data Resource | yes | https://cwe.mitre.org/data/definitions/1094.html |
| cwe_1095 | Loop Condition Value Update within the Loop | yes | https://cwe.mitre.org/data/definitions/1095.html |
| cwe_1096 | Singleton Class Instance Creation without Proper Locking or Synchronization | yes | https://cwe.mitre.org/data/definitions/1096.html |
| cwe_1097 | Persistent Storable Data Element without Associated Comparison Control Element | yes | https://cwe.mitre.org/data/definitions/1097.html |
| cwe_1098 | Data Element containing Pointer Item without Proper Copy Control Element | yes | https://cwe.mitre.org/data/definitions/1098.html |
| cwe_1099 | Inconsistent Naming Conventions for Identifiers | yes | https://cwe.mitre.org/data/definitions/1099.html |
| cwe_11 | ASP.NET Misconfiguration: Creating Debug Binary | yes | https://cwe.mitre.org/data/definitions/11.html |
| cwe_110 | Struts: Validator Without Form Field | yes | https://cwe.mitre.org/data/definitions/110.html |
| cwe_1100 | Insufficient Isolation of System-Dependent Functions | yes | https://cwe.mitre.org/data/definitions/1100.html |
| cwe_1101 | Reliance on Runtime Component in Generated Code | yes | https://cwe.mitre.org/data/definitions/1101.html |
| cwe_1102 | Reliance on Machine-Dependent Data Representation | yes | https://cwe.mitre.org/data/definitions/1102.html |
| cwe_1103 | Use of Platform-Dependent Third Party Components | yes | https://cwe.mitre.org/data/definitions/1103.html |
| cwe_1105 | Insufficient Encapsulation of Machine-Dependent Functionality | yes | https://cwe.mitre.org/data/definitions/1105.html |
| cwe_1106 | Insufficient Use of Symbolic Constants | yes | https://cwe.mitre.org/data/definitions/1106.html |
| cwe_1107 | Insufficient Isolation of Symbolic Constant Definitions | yes | https://cwe.mitre.org/data/definitions/1107.html |
| cwe_1108 | Excessive Reliance on Global Variables | yes | https://cwe.mitre.org/data/definitions/1108.html |
| cwe_1109 | Use of Same Variable for Multiple Purposes | yes | https://cwe.mitre.org/data/definitions/1109.html |
| cwe_111 | Direct Use of Unsafe JNI | yes | https://cwe.mitre.org/data/definitions/111.html |
| cwe_1110 | Incomplete Design Documentation | yes | https://cwe.mitre.org/data/definitions/1110.html |
| cwe_1111 | Incomplete I/O Documentation | yes | https://cwe.mitre.org/data/definitions/1111.html |
| cwe_1112 | Incomplete Documentation of Program Execution | yes | https://cwe.mitre.org/data/definitions/1112.html |
| cwe_1113 | Inappropriate Comment Style | yes | https://cwe.mitre.org/data/definitions/1113.html |
| cwe_1114 | Inappropriate Whitespace Style | yes | https://cwe.mitre.org/data/definitions/1114.html |
| cwe_1115 | Source Code Element without Standard Prologue | yes | https://cwe.mitre.org/data/definitions/1115.html |
| cwe_1116 | Inaccurate Source Code Comments | yes | https://cwe.mitre.org/data/definitions/1116.html |
| cwe_1117 | Callable with Insufficient Behavioral Summary | yes | https://cwe.mitre.org/data/definitions/1117.html |
| cwe_1118 | Insufficient Documentation of Error Handling Techniques | yes | https://cwe.mitre.org/data/definitions/1118.html |
| cwe_1119 | Excessive Use of Unconditional Branching | yes | https://cwe.mitre.org/data/definitions/1119.html |
| cwe_112 | Missing XML Validation | yes | https://cwe.mitre.org/data/definitions/112.html |
| cwe_1120 | Excessive Code Complexity | yes | https://cwe.mitre.org/data/definitions/1120.html |
| cwe_1121 | Excessive McCabe Cyclomatic Complexity | yes | https://cwe.mitre.org/data/definitions/1121.html |
| cwe_1122 | Excessive Halstead Complexity | yes | https://cwe.mitre.org/data/definitions/1122.html |
| cwe_1123 | Excessive Use of Self-Modifying Code | yes | https://cwe.mitre.org/data/definitions/1123.html |
| cwe_1124 | Excessively Deep Nesting | yes | https://cwe.mitre.org/data/definitions/1124.html |
| cwe_1125 | Excessive Attack Surface | yes | https://cwe.mitre.org/data/definitions/1125.html |
| cwe_1126 | Declaration of Variable with Unnecessarily Wide Scope | yes | https://cwe.mitre.org/data/definitions/1126.html |
| cwe_1127 | Compilation with Insufficient Warnings or Errors | yes | https://cwe.mitre.org/data/definitions/1127.html |
| cwe_114 | Process Control | yes | https://cwe.mitre.org/data/definitions/114.html |
| cwe_115 | Misinterpretation of Input | yes | https://cwe.mitre.org/data/definitions/115.html |
| cwe_116 | Improper Encoding or Escaping of Output | yes | https://cwe.mitre.org/data/definitions/116.html |
| cwe_1164 | Irrelevant Code | yes | https://cwe.mitre.org/data/definitions/1164.html |
| cwe_1173 | Improper Use of Validation Framework | yes | https://cwe.mitre.org/data/definitions/1173.html |
| cwe_1174 | ASP.NET Misconfiguration: Improper Model Validation | yes | https://cwe.mitre.org/data/definitions/1174.html |
| cwe_1176 | Inefficient CPU Computation | yes | https://cwe.mitre.org/data/definitions/1176.html |
| cwe_1177 | Use of Prohibited Code | yes | https://cwe.mitre.org/data/definitions/1177.html |
| cwe_118 | Incorrect Access of Indexable Resource | yes | https://cwe.mitre.org/data/definitions/118.html |
| cwe_1187 | DEPRECATED: Use of Uninitialized Resource | no | https://cwe.mitre.org/data/definitions/1187.html |
| cwe_1188 | Initialization of a Resource with an Insecure Default | yes | https://cwe.mitre.org/data/definitions/1188.html |
| cwe_1189 | Improper Isolation of Shared Resources on System-on-a-Chip (SoC) | yes | https://cwe.mitre.org/data/definitions/1189.html |
| cwe_119 | Improper Restriction of Operations within the Bounds of a Memory Buffer | yes | https://cwe.mitre.org/data/definitions/119.html |
| cwe_1190 | DMA Device Enabled Too Early in Boot Phase | yes | https://cwe.mitre.org/data/definitions/1190.html |
| cwe_1191 | On-Chip Debug and Test Interface With Improper Access Control | yes | https://cwe.mitre.org/data/definitions/1191.html |
| cwe_1192 | Improper Identifier for IP Block used in System-On-Chip (SOC) | yes | https://cwe.mitre.org/data/definitions/1192.html |
| cwe_1193 | Power-On of Untrusted Execution Core Before Enabling Fabric Access Control | yes | https://cwe.mitre.org/data/definitions/1193.html |
| cwe_12 | ASP.NET Misconfiguration: Missing Custom Error Page | yes | https://cwe.mitre.org/data/definitions/12.html |
| cwe_1204 | Generation of Weak Initialization Vector (IV) | yes | https://cwe.mitre.org/data/definitions/1204.html |
| cwe_1209 | Failure to Disable Reserved Bits | yes | https://cwe.mitre.org/data/definitions/1209.html |
| cwe_121 | Stack-based Buffer Overflow | yes | https://cwe.mitre.org/data/definitions/121.html |
| cwe_122 | Heap-based Buffer Overflow | yes | https://cwe.mitre.org/data/definitions/122.html |
| cwe_1220 | Insufficient Granularity of Access Control | yes | https://cwe.mitre.org/data/definitions/1220.html |
| cwe_1221 | Incorrect Register Defaults or Module Parameters | yes | https://cwe.mitre.org/data/definitions/1221.html |
| cwe_1222 | Insufficient Granularity of Address Regions Protected by Register Locks | yes | https://cwe.mitre.org/data/definitions/1222.html |
| cwe_1223 | Race Condition for Write-Once Attributes | yes | https://cwe.mitre.org/data/definitions/1223.html |
| cwe_1224 | Improper Restriction of Write-Once Bit Fields | yes | https://cwe.mitre.org/data/definitions/1224.html |
| cwe_1229 | Creation of Emergent Resource | yes | https://cwe.mitre.org/data/definitions/1229.html |
| cwe_123 | Write-what-where Condition | yes | https://cwe.mitre.org/data/definitions/123.html |
| cwe_1230 | Exposure of Sensitive Information Through Metadata | yes | https://cwe.mitre.org/data/definitions/1230.html |
| cwe_1231 | Improper Prevention of Lock Bit Modification | yes | https://cwe.mitre.org/data/definitions/1231.html |
| cwe_1232 | Improper Lock Behavior After Power State Transition | yes | https://cwe.mitre.org/data/definitions/1232.html |
| cwe_1233 | Security-Sensitive Hardware Controls with Missing Lock Bit Protection | yes | https://cwe.mitre.org/data/definitions/1233.html |
| cwe_1234 | Hardware Internal or Debug Modes Allow Override of Locks | yes | https://cwe.mitre.org/data/definitions/1234.html |
| cwe_1235 | Incorrect Use of Autoboxing and Unboxing for Performance Critical Operations | yes | https://cwe.mitre.org/data/definitions/1235.html |
| cwe_1239 | Improper Zeroization of Hardware Register | yes | https://cwe.mitre.org/data/definitions/1239.html |
| cwe_124 | Buffer Underwrite | yes | https://cwe.mitre.org/data/definitions/124.html |
| cwe_1240 | Use of a Cryptographic Primitive with a Risky Implementation | yes | https://cwe.mitre.org/data/definitions/1240.html |
| cwe_1241 | Use of Predictable Algorithm in Random Number Generator | yes | https://cwe.mitre.org/data/definitions/1241.html |
| cwe_1242 | Inclusion of Undocumented Features or Chicken Bits | yes | https://cwe.mitre.org/data/definitions/1242.html |
| cwe_1243 | Sensitive Non-Volatile Information Not Protected During Debug | yes | https://cwe.mitre.org/data/definitions/1243.html |
| cwe_1244 | Internal Asset Exposed to Unsafe Debug Access Level or State | yes | https://cwe.mitre.org/data/definitions/1244.html |
| cwe_1245 | Improper Finite State Machines (FSMs) in Hardware Logic | yes | https://cwe.mitre.org/data/definitions/1245.html |
| cwe_1246 | Improper Write Handling in Limited-write Non-Volatile Memories | yes | https://cwe.mitre.org/data/definitions/1246.html |
| cwe_1247 | Improper Protection Against Voltage and Clock Glitches | yes | https://cwe.mitre.org/data/definitions/1247.html |
| cwe_1248 | Semiconductor Defects in Hardware Logic with Security-Sensitive Implications | yes | https://cwe.mitre.org/data/definitions/1248.html |
| cwe_1249 | Application-Level Admin Tool with Inconsistent View of Underlying Operating System | yes | https://cwe.mitre.org/data/definitions/1249.html |
| cwe_1250 | Improper Preservation of Consistency Between Independent Representations of Shared State | yes | https://cwe.mitre.org/data/definitions/1250.html |
| cwe_1251 | Mirrored Regions with Different Values | yes | https://cwe.mitre.org/data/definitions/1251.html |
| cwe_1252 | CPU Hardware Not Configured to Support Exclusivity of Write and Execute Operations | yes | https://cwe.mitre.org/data/definitions/1252.html |
| cwe_1253 | Incorrect Selection of Fuse Values | yes | https://cwe.mitre.org/data/definitions/1253.html |
| cwe_1254 | Incorrect Comparison Logic Granularity | yes | https://cwe.mitre.org/data/definitions/1254.html |
| cwe_1255 | Comparison Logic is Vulnerable to Power Side-Channel Attacks | yes | https://cwe.mitre.org/data/definitions/1255.html |
| cwe_1256 | Improper Restriction of Software Interfaces to Hardware Features | yes | https://cwe.mitre.org/data/definitions/1256.html |
| cwe_1257 | Improper Access Control Applied to Mirrored or Aliased Memory Regions | yes | https://cwe.mitre.org/data/definitions/1257.html |
| cwe_1258 | Exposure of Sensitive System Information Due to Uncleared Debug Information | yes | https://cwe.mitre.org/data/definitions/1258.html |
| cwe_1259 | Improper Restriction of Security Token Assignment | yes | https://cwe.mitre.org/data/definitions/1259.html |
| cwe_126 | Buffer Over-read | yes | https://cwe.mitre.org/data/definitions/126.html |
| cwe_1260 | Improper Handling of Overlap Between Protected Memory Ranges | yes | https://cwe.mitre.org/data/definitions/1260.html |
| cwe_1261 | Improper Handling of Single Event Upsets | yes | https://cwe.mitre.org/data/definitions/1261.html |
| cwe_1262 | Improper Access Control for Register Interface | yes | https://cwe.mitre.org/data/definitions/1262.html |
| cwe_1263 | Improper Physical Access Control | yes | https://cwe.mitre.org/data/definitions/1263.html |
| cwe_1264 | Hardware Logic with Insecure De-Synchronization between Control and Data Channels | yes | https://cwe.mitre.org/data/definitions/1264.html |
| cwe_1265 | Unintended Reentrant Invocation of Non-reentrant Code Via Nested Calls | yes | https://cwe.mitre.org/data/definitions/1265.html |
| cwe_1266 | Improper Scrubbing of Sensitive Data from Decommissioned Device | yes | https://cwe.mitre.org/data/definitions/1266.html |
| cwe_1267 | Policy Uses Obsolete Encoding | yes | https://cwe.mitre.org/data/definitions/1267.html |
| cwe_1268 | Policy Privileges are not Assigned Consistently Between Control and Data Agents | yes | https://cwe.mitre.org/data/definitions/1268.html |
| cwe_1269 | Product Released in Non-Release Configuration | yes | https://cwe.mitre.org/data/definitions/1269.html |
| cwe_127 | Buffer Under-read | yes | https://cwe.mitre.org/data/definitions/127.html |
| cwe_1270 | Generation of Incorrect Security Tokens | yes | https://cwe.mitre.org/data/definitions/1270.html |
| cwe_1271 | Uninitialized Value on Reset for Registers Holding Security Settings | yes | https://cwe.mitre.org/data/definitions/1271.html |
| cwe_1272 | Sensitive Information Uncleared Before Debug/Power State Transition | yes | https://cwe.mitre.org/data/definitions/1272.html |
| cwe_1273 | Device Unlock Credential Sharing | yes | https://cwe.mitre.org/data/definitions/1273.html |
| cwe_1274 | Improper Access Control for Volatile Memory Containing Boot Code | yes | https://cwe.mitre.org/data/definitions/1274.html |
| cwe_1275 | Sensitive Cookie with Improper SameSite Attribute | yes | https://cwe.mitre.org/data/definitions/1275.html |
| cwe_1276 | Hardware Child Block Incorrectly Connected to Parent System | yes | https://cwe.mitre.org/data/definitions/1276.html |
| cwe_1277 | Firmware Not Updateable | yes | https://cwe.mitre.org/data/definitions/1277.html |
| cwe_1278 | Missing Protection Against Hardware Reverse Engineering Using Integrated Circuit (IC) Imaging Techniques | yes | https://cwe.mitre.org/data/definitions/1278.html |
| cwe_1279 | Cryptographic Operations are Run Before Supporting Units are Ready | yes | https://cwe.mitre.org/data/definitions/1279.html |
| cwe_128 | Wrap-around Error | yes | https://cwe.mitre.org/data/definitions/128.html |
| cwe_1280 | Access Control Check Implemented After Asset is Accessed | yes | https://cwe.mitre.org/data/definitions/1280.html |
| cwe_1281 | Sequence of Processor Instructions Leads to Unexpected Behavior | yes | https://cwe.mitre.org/data/definitions/1281.html |
| cwe_1282 | Assumed-Immutable Data is Stored in Writable Memory | yes | https://cwe.mitre.org/data/definitions/1282.html |
| cwe_1283 | Mutable Attestation or Measurement Reporting Data | yes | https://cwe.mitre.org/data/definitions/1283.html |
| cwe_1284 | Improper Validation of Specified Quantity in Input | yes | https://cwe.mitre.org/data/definitions/1284.html |
| cwe_1285 | Improper Validation of Specified Index, Position, or Offset in Input | yes | https://cwe.mitre.org/data/definitions/1285.html |
| cwe_1286 | Improper Validation of Syntactic Correctness of Input | yes | https://cwe.mitre.org/data/definitions/1286.html |
| cwe_1287 | Improper Validation of Specified Type of Input | yes | https://cwe.mitre.org/data/definitions/1287.html |
| cwe_1288 | Improper Validation of Consistency within Input | yes | https://cwe.mitre.org/data/definitions/1288.html |
| cwe_1289 | Improper Validation of Unsafe Equivalence in Input | yes | https://cwe.mitre.org/data/definitions/1289.html |
| cwe_129 | Improper Validation of Array Index | yes | https://cwe.mitre.org/data/definitions/129.html |
| cwe_1290 | Incorrect Decoding of Security Identifiers | yes | https://cwe.mitre.org/data/definitions/1290.html |
| cwe_1291 | Public Key Re-Use for Signing both Debug and Production Code | yes | https://cwe.mitre.org/data/definitions/1291.html |
| cwe_1292 | Incorrect Conversion of Security Identifiers | yes | https://cwe.mitre.org/data/definitions/1292.html |
| cwe_1293 | Missing Source Correlation of Multiple Independent Data | yes | https://cwe.mitre.org/data/definitions/1293.html |
| cwe_1294 | Insecure Security Identifier Mechanism | yes | https://cwe.mitre.org/data/definitions/1294.html |
| cwe_1295 | Debug Messages Revealing Unnecessary Information | yes | https://cwe.mitre.org/data/definitions/1295.html |
| cwe_1296 | Incorrect Chaining or Granularity of Debug Components | yes | https://cwe.mitre.org/data/definitions/1296.html |
| cwe_1297 | Unprotected Confidential Information on Device is Accessible by OSAT Vendors | yes | https://cwe.mitre.org/data/definitions/1297.html |
| cwe_1298 | Hardware Logic Contains Race Conditions | yes | https://cwe.mitre.org/data/definitions/1298.html |
| cwe_1299 | Missing Protection Mechanism for Alternate Hardware Interface | yes | https://cwe.mitre.org/data/definitions/1299.html |
| cwe_13 | ASP.NET Misconfiguration: Password in Configuration File | yes | https://cwe.mitre.org/data/definitions/13.html |
| cwe_130 | Improper Handling of Length Parameter Inconsistency | yes | https://cwe.mitre.org/data/definitions/130.html |
| cwe_1300 | Improper Protection of Physical Side Channels | yes | https://cwe.mitre.org/data/definitions/1300.html |
| cwe_1301 | Insufficient or Incomplete Data Removal within Hardware Component | yes | https://cwe.mitre.org/data/definitions/1301.html |
| cwe_1302 | Missing Source Identifier in Entity Transactions on a System-On-Chip (SOC) | yes | https://cwe.mitre.org/data/definitions/1302.html |
| cwe_1303 | Non-Transparent Sharing of Microarchitectural Resources | yes | https://cwe.mitre.org/data/definitions/1303.html |
| cwe_1304 | Improperly Preserved Integrity of Hardware Configuration State During a Power Save/Restore Operation | yes | https://cwe.mitre.org/data/definitions/1304.html |
| cwe_131 | Incorrect Calculation of Buffer Size | yes | https://cwe.mitre.org/data/definitions/131.html |
| cwe_1310 | Missing Ability to Patch ROM Code | yes | https://cwe.mitre.org/data/definitions/1310.html |
| cwe_1311 | Improper Translation of Security Attributes by Fabric Bridge | yes | https://cwe.mitre.org/data/definitions/1311.html |
| cwe_1312 | Missing Protection for Mirrored Regions in On-Chip Fabric Firewall | yes | https://cwe.mitre.org/data/definitions/1312.html |
| cwe_1313 | Hardware Allows Activation of Test or Debug Logic at Runtime | yes | https://cwe.mitre.org/data/definitions/1313.html |
| cwe_1314 | Missing Write Protection for Parametric Data Values | yes | https://cwe.mitre.org/data/definitions/1314.html |
| cwe_1315 | Improper Setting of Bus Controlling Capability in Fabric End-point | yes | https://cwe.mitre.org/data/definitions/1315.html |
| cwe_1316 | Fabric-Address Map Allows Programming of Unwarranted Overlaps of Protected and Unprotected Ranges | yes | https://cwe.mitre.org/data/definitions/1316.html |
| cwe_1317 | Improper Access Control in Fabric Bridge | yes | https://cwe.mitre.org/data/definitions/1317.html |
| cwe_1318 | Missing Support for Security Features in On-chip Fabrics or Buses | yes | https://cwe.mitre.org/data/definitions/1318.html |
| cwe_1319 | Improper Protection against Electromagnetic Fault Injection (EM-FI) | yes | https://cwe.mitre.org/data/definitions/1319.html |
| cwe_132 | DEPRECATED: Miscalculated Null Termination | no | https://cwe.mitre.org/data/definitions/132.html |
| cwe_1320 | Improper Protection for Outbound Error Messages and Alert Signals | yes | https://cwe.mitre.org/data/definitions/1320.html |
| cwe_1321 | Improperly Controlled Modification of Object Prototype Attributes | yes | https://cwe.mitre.org/data/definitions/1321.html |
| cwe_1322 | Use of Blocking Code in Single-threaded, Non-blocking Context | yes | https://cwe.mitre.org/data/definitions/1322.html |
| cwe_1323 | Improper Management of Sensitive Trace Data | yes | https://cwe.mitre.org/data/definitions/1323.html |
| cwe_1324 | DEPRECATED: Sensitive Information Accessible by Physical Probing of JTAG Interface | no | https://cwe.mitre.org/data/definitions/1324.html |
| cwe_1325 | Improperly Controlled Sequential Memory Allocation | yes | https://cwe.mitre.org/data/definitions/1325.html |
| cwe_1326 | Missing Immutable Root of Trust in Hardware | yes | https://cwe.mitre.org/data/definitions/1326.html |
| cwe_1327 | Binding to an Unrestricted IP Address | yes | https://cwe.mitre.org/data/definitions/1327.html |
| cwe_1328 | Security Version Number Mutable to Older Versions | yes | https://cwe.mitre.org/data/definitions/1328.html |
| cwe_1329 | Reliance on Component That is Not Updateable | yes | https://cwe.mitre.org/data/definitions/1329.html |
| cwe_1330 | Remanent Data Readable after Memory Erase | yes | https://cwe.mitre.org/data/definitions/1330.html |
| cwe_1331 | Improper Isolation of Shared Resources in Network On Chip (NoC) | yes | https://cwe.mitre.org/data/definitions/1331.html |
| cwe_1332 | Improper Handling of Faults that Lead to Instruction Skips | yes | https://cwe.mitre.org/data/definitions/1332.html |
| cwe_1334 | Unauthorized Error Injection Can Degrade Hardware Redundancy | yes | https://cwe.mitre.org/data/definitions/1334.html |
| cwe_1335 | Incorrect Bitwise Shift of Integer | yes | https://cwe.mitre.org/data/definitions/1335.html |
| cwe_1338 | Improper Protections Against Hardware Overheating | yes | https://cwe.mitre.org/data/definitions/1338.html |
| cwe_1339 | Insufficient Precision or Accuracy of a Real Number | yes | https://cwe.mitre.org/data/definitions/1339.html |
| cwe_134 | Use of Externally-Controlled Format String | yes | https://cwe.mitre.org/data/definitions/134.html |
| cwe_1341 | Multiple Releases of Same Resource or Handle | yes | https://cwe.mitre.org/data/definitions/1341.html |
| cwe_1342 | Information Exposure through Microarchitectural State after Transient Execution | yes | https://cwe.mitre.org/data/definitions/1342.html |
| cwe_135 | Incorrect Calculation of Multi-Byte String Length | yes | https://cwe.mitre.org/data/definitions/135.html |
| cwe_1351 | Improper Handling of Hardware Behavior in Exceptionally Cold Environments | yes | https://cwe.mitre.org/data/definitions/1351.html |
| cwe_1357 | Reliance on Insufficiently Trustworthy Component | yes | https://cwe.mitre.org/data/definitions/1357.html |
| cwe_138 | Improper Neutralization of Special Elements | yes | https://cwe.mitre.org/data/definitions/138.html |
| cwe_1384 | Improper Handling of Physical or Environmental Conditions | yes | https://cwe.mitre.org/data/definitions/1384.html |
| cwe_1385 | Missing Origin Validation in WebSockets | yes | https://cwe.mitre.org/data/definitions/1385.html |
| cwe_1386 | Insecure Operation on Windows Junction / Mount Point | yes | https://cwe.mitre.org/data/definitions/1386.html |
| cwe_1389 | Incorrect Parsing of Numbers with Different Radices | yes | https://cwe.mitre.org/data/definitions/1389.html |
| cwe_1390 | Weak Authentication | yes | https://cwe.mitre.org/data/definitions/1390.html |
| cwe_1391 | Use of Weak Credentials | yes | https://cwe.mitre.org/data/definitions/1391.html |
| cwe_1392 | Use of Default Credentials | yes | https://cwe.mitre.org/data/definitions/1392.html |
| cwe_1393 | Use of Default Password | yes | https://cwe.mitre.org/data/definitions/1393.html |
| cwe_1394 | Use of Default Cryptographic Key | yes | https://cwe.mitre.org/data/definitions/1394.html |
| cwe_14 | Compiler Removal of Code to Clear Buffers | yes | https://cwe.mitre.org/data/definitions/14.html |
| cwe_140 | Improper Neutralization of Delimiters | yes | https://cwe.mitre.org/data/definitions/140.html |
| cwe_141 | Improper Neutralization of Parameter/Argument Delimiters | yes | https://cwe.mitre.org/data/definitions/141.html |
| cwe_1419 | Incorrect Initialization of Resource | yes | https://cwe.mitre.org/data/definitions/1419.html |
| cwe_142 | Improper Neutralization of Value Delimiters | yes | https://cwe.mitre.org/data/definitions/142.html |
| cwe_1420 | Exposure of Sensitive Information during Transient Execution | yes | https://cwe.mitre.org/data/definitions/1420.html |
| cwe_1421 | Exposure of Sensitive Information in Shared Microarchitectural Structures during Transient Execution | yes | https://cwe.mitre.org/data/definitions/1421.html |
| cwe_1422 | Exposure of Sensitive Information caused by Incorrect Data Forwarding during Transient Execution | yes | https://cwe.mitre.org/data/definitions/1422.html |
| cwe_1423 | Exposure of Sensitive Information caused by Shared Microarchitectural Predictor State that Influences Transient Execution | yes | https://cwe.mitre.org/data/definitions/1423.html |
| cwe_1428 | Reliance on HTTP instead of HTTPS | yes | https://cwe.mitre.org/data/definitions/1428.html |
| cwe_1429 | Missing Security-Relevant Feedback for Unexecuted Operations in Hardware Interface | yes | https://cwe.mitre.org/data/definitions/1429.html |
| cwe_143 | Improper Neutralization of Record Delimiters | yes | https://cwe.mitre.org/data/definitions/143.html |
| cwe_1431 | Driving Intermediate Cryptographic State/Results to Hardware Module Outputs | yes | https://cwe.mitre.org/data/definitions/1431.html |
| cwe_1434 | Insecure Setting of Generative AI/ML Model Inference Parameters | yes | https://cwe.mitre.org/data/definitions/1434.html |
| cwe_144 | Improper Neutralization of Line Delimiters | yes | https://cwe.mitre.org/data/definitions/144.html |
| cwe_145 | Improper Neutralization of Section Delimiters | yes | https://cwe.mitre.org/data/definitions/145.html |
| cwe_146 | Improper Neutralization of Expression/Command Delimiters | yes | https://cwe.mitre.org/data/definitions/146.html |
| cwe_1461 | Hardware Simulation / Synthesis Mismatch | yes | https://cwe.mitre.org/data/definitions/1461.html |
| cwe_1462 | Improper Session Management | yes | https://cwe.mitre.org/data/definitions/1462.html |
| cwe_1463 | Insufficient Session Timeout Value | yes | https://cwe.mitre.org/data/definitions/1463.html |
| cwe_1464 | Improper Session Invalidation | yes | https://cwe.mitre.org/data/definitions/1464.html |
| cwe_1465 | Improper Session Invalidation after User Logout | yes | https://cwe.mitre.org/data/definitions/1465.html |
| cwe_1466 | Improper Session Invalidation after Authentication Credential Change | yes | https://cwe.mitre.org/data/definitions/1466.html |
| cwe_1467 | Use of Singular Authentication Artifact for Multiple User Sessions | yes | https://cwe.mitre.org/data/definitions/1467.html |
| cwe_1469 | Improper Check for Credential Expiration | yes | https://cwe.mitre.org/data/definitions/1469.html |
| cwe_147 | Improper Neutralization of Input Terminators | yes | https://cwe.mitre.org/data/definitions/147.html |
| cwe_1470 | Improper External Identity Verification | yes | https://cwe.mitre.org/data/definitions/1470.html |
| cwe_1471 | Insufficiently Controlled Parser Differential | yes | https://cwe.mitre.org/data/definitions/1471.html |
| cwe_1472 | Generation of Credential with Long Expiration | yes | https://cwe.mitre.org/data/definitions/1472.html |
| cwe_1473 | Improper Expiration of Cached Data | yes | https://cwe.mitre.org/data/definitions/1473.html |
| cwe_1474 | Non-Equivalent Data Transformation | yes | https://cwe.mitre.org/data/definitions/1474.html |
| cwe_1475 | Incomplete Data/State Propagation | yes | https://cwe.mitre.org/data/definitions/1475.html |
| cwe_1476 | Improper Request Propagation before Data Reception in Write Transactions in a Bus Architecture | yes | https://cwe.mitre.org/data/definitions/1476.html |
| cwe_148 | Improper Neutralization of Input Leaders | yes | https://cwe.mitre.org/data/definitions/148.html |
| cwe_149 | Improper Neutralization of Quoting Syntax | yes | https://cwe.mitre.org/data/definitions/149.html |
| cwe_15 | External Control of System or Configuration Setting | yes | https://cwe.mitre.org/data/definitions/15.html |
| cwe_150 | Improper Neutralization of Escape, Meta, or Control Sequences | yes | https://cwe.mitre.org/data/definitions/150.html |
| cwe_151 | Improper Neutralization of Comment Delimiters | yes | https://cwe.mitre.org/data/definitions/151.html |
| cwe_152 | Improper Neutralization of Macro Symbols | yes | https://cwe.mitre.org/data/definitions/152.html |
| cwe_153 | Improper Neutralization of Substitution Characters | yes | https://cwe.mitre.org/data/definitions/153.html |
| cwe_154 | Improper Neutralization of Variable Name Delimiters | yes | https://cwe.mitre.org/data/definitions/154.html |
| cwe_155 | Improper Neutralization of Wildcards or Matching Symbols | yes | https://cwe.mitre.org/data/definitions/155.html |
| cwe_156 | Improper Neutralization of Whitespace | yes | https://cwe.mitre.org/data/definitions/156.html |
| cwe_157 | Failure to Sanitize Paired Delimiters | yes | https://cwe.mitre.org/data/definitions/157.html |
| cwe_158 | Improper Neutralization of Null Byte or NUL Character | yes | https://cwe.mitre.org/data/definitions/158.html |
| cwe_159 | Improper Handling of Invalid Use of Special Elements | yes | https://cwe.mitre.org/data/definitions/159.html |
| cwe_160 | Improper Neutralization of Leading Special Elements | yes | https://cwe.mitre.org/data/definitions/160.html |
| cwe_161 | Improper Neutralization of Multiple Leading Special Elements | yes | https://cwe.mitre.org/data/definitions/161.html |
| cwe_162 | Improper Neutralization of Trailing Special Elements | yes | https://cwe.mitre.org/data/definitions/162.html |
| cwe_163 | Improper Neutralization of Multiple Trailing Special Elements | yes | https://cwe.mitre.org/data/definitions/163.html |
| cwe_164 | Improper Neutralization of Internal Special Elements | yes | https://cwe.mitre.org/data/definitions/164.html |
| cwe_165 | Improper Neutralization of Multiple Internal Special Elements | yes | https://cwe.mitre.org/data/definitions/165.html |
| cwe_166 | Improper Handling of Missing Special Element | yes | https://cwe.mitre.org/data/definitions/166.html |
| cwe_167 | Improper Handling of Additional Special Element | yes | https://cwe.mitre.org/data/definitions/167.html |
| cwe_168 | Improper Handling of Inconsistent Special Elements | yes | https://cwe.mitre.org/data/definitions/168.html |
| cwe_170 | Improper Null Termination | yes | https://cwe.mitre.org/data/definitions/170.html |
| cwe_172 | Improper Encoding or Decoding of Data | yes | https://cwe.mitre.org/data/definitions/172.html |
| cwe_173 | Improper Handling of Alternate Encoding | yes | https://cwe.mitre.org/data/definitions/173.html |
| cwe_174 | Double Decoding of the Same Data | yes | https://cwe.mitre.org/data/definitions/174.html |
| cwe_175 | Improper Handling of Mixed Encoding | yes | https://cwe.mitre.org/data/definitions/175.html |
| cwe_176 | Improper Handling of Unicode Encoding | yes | https://cwe.mitre.org/data/definitions/176.html |
| cwe_177 | Improper Handling of URL Encoding (Hex Encoding) | yes | https://cwe.mitre.org/data/definitions/177.html |
| cwe_178 | Improper Handling of Case Sensitivity | yes | https://cwe.mitre.org/data/definitions/178.html |
| cwe_179 | Incorrect Behavior Order: Early Validation | yes | https://cwe.mitre.org/data/definitions/179.html |
| cwe_180 | Incorrect Behavior Order: Validate Before Canonicalize | yes | https://cwe.mitre.org/data/definitions/180.html |
| cwe_181 | Incorrect Behavior Order: Validate Before Filter | yes | https://cwe.mitre.org/data/definitions/181.html |
| cwe_182 | Collapse of Data into Unsafe Value | yes | https://cwe.mitre.org/data/definitions/182.html |
| cwe_183 | Permissive List of Allowed Inputs | yes | https://cwe.mitre.org/data/definitions/183.html |
| cwe_184 | Incomplete List of Disallowed Inputs | yes | https://cwe.mitre.org/data/definitions/184.html |
| cwe_185 | Incorrect Regular Expression | yes | https://cwe.mitre.org/data/definitions/185.html |
| cwe_186 | Overly Restrictive Regular Expression | yes | https://cwe.mitre.org/data/definitions/186.html |
| cwe_187 | Partial String Comparison | yes | https://cwe.mitre.org/data/definitions/187.html |
| cwe_188 | Reliance on Data/Memory Layout | yes | https://cwe.mitre.org/data/definitions/188.html |
| cwe_191 | Integer Underflow (Wrap or Wraparound) | yes | https://cwe.mitre.org/data/definitions/191.html |
| cwe_192 | Integer Coercion Error | yes | https://cwe.mitre.org/data/definitions/192.html |
| cwe_193 | Off-by-one Error | yes | https://cwe.mitre.org/data/definitions/193.html |
| cwe_194 | Unexpected Sign Extension | yes | https://cwe.mitre.org/data/definitions/194.html |
| cwe_195 | Signed to Unsigned Conversion Error | yes | https://cwe.mitre.org/data/definitions/195.html |
| cwe_196 | Unsigned to Signed Conversion Error | yes | https://cwe.mitre.org/data/definitions/196.html |
| cwe_197 | Numeric Truncation Error | yes | https://cwe.mitre.org/data/definitions/197.html |
| cwe_198 | Use of Incorrect Byte Ordering | yes | https://cwe.mitre.org/data/definitions/198.html |
| cwe_20 | Improper Input Validation | yes | https://cwe.mitre.org/data/definitions/20.html |
| cwe_201 | Insertion of Sensitive Information Into Sent Data | yes | https://cwe.mitre.org/data/definitions/201.html |
| cwe_202 | Exposure of Sensitive Information Through Data Queries | yes | https://cwe.mitre.org/data/definitions/202.html |
| cwe_203 | Observable Discrepancy | yes | https://cwe.mitre.org/data/definitions/203.html |
| cwe_204 | Observable Response Discrepancy | yes | https://cwe.mitre.org/data/definitions/204.html |
| cwe_205 | Observable Behavioral Discrepancy | yes | https://cwe.mitre.org/data/definitions/205.html |
| cwe_206 | Observable Internal Behavioral Discrepancy | yes | https://cwe.mitre.org/data/definitions/206.html |
| cwe_207 | Observable Behavioral Discrepancy With Equivalent Products | yes | https://cwe.mitre.org/data/definitions/207.html |
| cwe_210 | Self-generated Error Message Containing Sensitive Information | yes | https://cwe.mitre.org/data/definitions/210.html |
| cwe_211 | Externally-Generated Error Message Containing Sensitive Information | yes | https://cwe.mitre.org/data/definitions/211.html |
| cwe_212 | Improper Removal of Sensitive Information Before Storage or Transfer | yes | https://cwe.mitre.org/data/definitions/212.html |
| cwe_213 | Exposure of Sensitive Information Due to Incompatible Policies | yes | https://cwe.mitre.org/data/definitions/213.html |
| cwe_214 | Invocation of Process Using Visible Sensitive Information | yes | https://cwe.mitre.org/data/definitions/214.html |
| cwe_215 | Insertion of Sensitive Information Into Debugging Code | yes | https://cwe.mitre.org/data/definitions/215.html |
| cwe_216 | DEPRECATED: Containment Errors (Container Errors) | no | https://cwe.mitre.org/data/definitions/216.html |
| cwe_217 | DEPRECATED: Failure to Protect Stored Data from Modification | no | https://cwe.mitre.org/data/definitions/217.html |
| cwe_218 | DEPRECATED: Failure to provide confidentiality for stored data | no | https://cwe.mitre.org/data/definitions/218.html |
| cwe_219 | Storage of File with Sensitive Data Under Web Root | yes | https://cwe.mitre.org/data/definitions/219.html |
| cwe_220 | Storage of File With Sensitive Data Under FTP Root | yes | https://cwe.mitre.org/data/definitions/220.html |
| cwe_221 | Information Loss or Omission | yes | https://cwe.mitre.org/data/definitions/221.html |
| cwe_222 | Truncation of Security-relevant Information | yes | https://cwe.mitre.org/data/definitions/222.html |
| cwe_223 | Omission of Security-relevant Information | yes | https://cwe.mitre.org/data/definitions/223.html |
| cwe_224 | Obscured Security-relevant Information by Alternate Name | yes | https://cwe.mitre.org/data/definitions/224.html |
| cwe_225 | DEPRECATED: General Information Management Problems | no | https://cwe.mitre.org/data/definitions/225.html |
| cwe_226 | Sensitive Information in Resource Not Removed Before Reuse | yes | https://cwe.mitre.org/data/definitions/226.html |
| cwe_228 | Improper Handling of Syntactically Invalid Structure | yes | https://cwe.mitre.org/data/definitions/228.html |
| cwe_229 | Improper Handling of Values | yes | https://cwe.mitre.org/data/definitions/229.html |
| cwe_23 | Relative Path Traversal | yes | https://cwe.mitre.org/data/definitions/23.html |
| cwe_230 | Improper Handling of Missing Values | yes | https://cwe.mitre.org/data/definitions/230.html |
| cwe_231 | Improper Handling of Extra Values | yes | https://cwe.mitre.org/data/definitions/231.html |
| cwe_232 | Improper Handling of Undefined Values | yes | https://cwe.mitre.org/data/definitions/232.html |
| cwe_233 | Improper Handling of Parameters | yes | https://cwe.mitre.org/data/definitions/233.html |
| cwe_234 | Failure to Handle Missing Parameter | yes | https://cwe.mitre.org/data/definitions/234.html |
| cwe_235 | Improper Handling of Extra Parameters | yes | https://cwe.mitre.org/data/definitions/235.html |
| cwe_236 | Improper Handling of Undefined Parameters | yes | https://cwe.mitre.org/data/definitions/236.html |
| cwe_237 | Improper Handling of Structural Elements | yes | https://cwe.mitre.org/data/definitions/237.html |
| cwe_238 | Improper Handling of Incomplete Structural Elements | yes | https://cwe.mitre.org/data/definitions/238.html |
| cwe_239 | Failure to Handle Incomplete Element | yes | https://cwe.mitre.org/data/definitions/239.html |
| cwe_24 | Path Traversal: '../filedir' | yes | https://cwe.mitre.org/data/definitions/24.html |
| cwe_240 | Improper Handling of Inconsistent Structural Elements | yes | https://cwe.mitre.org/data/definitions/240.html |
| cwe_241 | Improper Handling of Unexpected Data Type | yes | https://cwe.mitre.org/data/definitions/241.html |
| cwe_242 | Use of Inherently Dangerous Function | yes | https://cwe.mitre.org/data/definitions/242.html |
| cwe_243 | Creation of chroot Jail Without Changing Working Directory | yes | https://cwe.mitre.org/data/definitions/243.html |
| cwe_244 | Improper Clearing of Heap Memory Before Release | yes | https://cwe.mitre.org/data/definitions/244.html |
| cwe_245 | J2EE Bad Practices: Direct Management of Connections | yes | https://cwe.mitre.org/data/definitions/245.html |
| cwe_246 | J2EE Bad Practices: Direct Use of Sockets | yes | https://cwe.mitre.org/data/definitions/246.html |
| cwe_247 | DEPRECATED: Reliance on DNS Lookups in a Security Decision | no | https://cwe.mitre.org/data/definitions/247.html |
| cwe_248 | Uncaught Exception | yes | https://cwe.mitre.org/data/definitions/248.html |
| cwe_249 | DEPRECATED: Often Misused: Path Manipulation | no | https://cwe.mitre.org/data/definitions/249.html |
| cwe_25 | Path Traversal: '/../filedir' | yes | https://cwe.mitre.org/data/definitions/25.html |
| cwe_250 | Execution with Unnecessary Privileges | yes | https://cwe.mitre.org/data/definitions/250.html |
| cwe_252 | Unchecked Return Value | yes | https://cwe.mitre.org/data/definitions/252.html |
| cwe_253 | Incorrect Check of Function Return Value | yes | https://cwe.mitre.org/data/definitions/253.html |
| cwe_256 | Plaintext Storage of a Password | yes | https://cwe.mitre.org/data/definitions/256.html |
| cwe_257 | Storing Passwords in a Recoverable Format | yes | https://cwe.mitre.org/data/definitions/257.html |
| cwe_258 | Empty Password in Configuration File | yes | https://cwe.mitre.org/data/definitions/258.html |
| cwe_259 | Use of Hard-coded Password | yes | https://cwe.mitre.org/data/definitions/259.html |
| cwe_26 | Path Traversal: '/dir/../filename' | yes | https://cwe.mitre.org/data/definitions/26.html |
| cwe_260 | Password in Configuration File | yes | https://cwe.mitre.org/data/definitions/260.html |
| cwe_261 | Weak Encoding for Password | yes | https://cwe.mitre.org/data/definitions/261.html |
| cwe_262 | Not Using Password Aging | yes | https://cwe.mitre.org/data/definitions/262.html |
| cwe_263 | Password Aging with Long Expiration | yes | https://cwe.mitre.org/data/definitions/263.html |
| cwe_266 | Incorrect Privilege Assignment | yes | https://cwe.mitre.org/data/definitions/266.html |
| cwe_267 | Privilege Defined With Unsafe Actions | yes | https://cwe.mitre.org/data/definitions/267.html |
| cwe_268 | Privilege Chaining | yes | https://cwe.mitre.org/data/definitions/268.html |
| cwe_27 | Path Traversal: 'dir/../../filename' | yes | https://cwe.mitre.org/data/definitions/27.html |
| cwe_270 | Privilege Context Switching Error | yes | https://cwe.mitre.org/data/definitions/270.html |
| cwe_271 | Privilege Dropping / Lowering Errors | yes | https://cwe.mitre.org/data/definitions/271.html |
| cwe_272 | Least Privilege Violation | yes | https://cwe.mitre.org/data/definitions/272.html |
| cwe_273 | Improper Check for Dropped Privileges | yes | https://cwe.mitre.org/data/definitions/273.html |
| cwe_274 | Improper Handling of Insufficient Privileges | yes | https://cwe.mitre.org/data/definitions/274.html |
| cwe_276 | Incorrect Default Permissions | yes | https://cwe.mitre.org/data/definitions/276.html |
| cwe_277 | Insecure Inherited Permissions | yes | https://cwe.mitre.org/data/definitions/277.html |
| cwe_278 | Insecure Preserved Inherited Permissions | yes | https://cwe.mitre.org/data/definitions/278.html |
| cwe_279 | Incorrect Execution-Assigned Permissions | yes | https://cwe.mitre.org/data/definitions/279.html |
| cwe_28 | Path Traversal: '..\filedir' | yes | https://cwe.mitre.org/data/definitions/28.html |
| cwe_280 | Improper Handling of Insufficient Permissions or Privileges | yes | https://cwe.mitre.org/data/definitions/280.html |
| cwe_281 | Improper Preservation of Permissions | yes | https://cwe.mitre.org/data/definitions/281.html |
| cwe_282 | Improper Ownership Management | yes | https://cwe.mitre.org/data/definitions/282.html |
| cwe_283 | Unverified Ownership | yes | https://cwe.mitre.org/data/definitions/283.html |
| cwe_284 | Improper Access Control | no | https://cwe.mitre.org/data/definitions/284.html |
| cwe_285 | Improper Authorization | yes | https://cwe.mitre.org/data/definitions/285.html |
| cwe_286 | Incorrect User Management | yes | https://cwe.mitre.org/data/definitions/286.html |
| cwe_288 | Authentication Bypass Using an Alternate Path or Channel | yes | https://cwe.mitre.org/data/definitions/288.html |
| cwe_289 | Authentication Bypass by Alternate Name | yes | https://cwe.mitre.org/data/definitions/289.html |
| cwe_29 | Path Traversal: '\..\filename' | yes | https://cwe.mitre.org/data/definitions/29.html |
| cwe_290 | Authentication Bypass by Spoofing | yes | https://cwe.mitre.org/data/definitions/290.html |
| cwe_291 | Reliance on IP Address for Authentication | yes | https://cwe.mitre.org/data/definitions/291.html |
| cwe_292 | DEPRECATED: Trusting Self-reported DNS Name | no | https://cwe.mitre.org/data/definitions/292.html |
| cwe_293 | Using Referer Field for Authentication | yes | https://cwe.mitre.org/data/definitions/293.html |
| cwe_294 | Authentication Bypass by Capture-replay | yes | https://cwe.mitre.org/data/definitions/294.html |
| cwe_296 | Improper Following of a Certificate's Chain of Trust | yes | https://cwe.mitre.org/data/definitions/296.html |
| cwe_297 | Improper Validation of Certificate with Host Mismatch | yes | https://cwe.mitre.org/data/definitions/297.html |
| cwe_298 | Improper Validation of Certificate Expiration | yes | https://cwe.mitre.org/data/definitions/298.html |
| cwe_299 | Improper Check for Certificate Revocation | yes | https://cwe.mitre.org/data/definitions/299.html |
| cwe_30 | Path Traversal: '\dir\..\filename' | yes | https://cwe.mitre.org/data/definitions/30.html |
| cwe_300 | Channel Accessible by Non-Endpoint | yes | https://cwe.mitre.org/data/definitions/300.html |
| cwe_301 | Reflection Attack in an Authentication Protocol | yes | https://cwe.mitre.org/data/definitions/301.html |
| cwe_302 | Authentication Bypass by Assumed-Immutable Data | yes | https://cwe.mitre.org/data/definitions/302.html |
| cwe_303 | Incorrect Implementation of Authentication Algorithm | yes | https://cwe.mitre.org/data/definitions/303.html |
| cwe_304 | Missing Critical Step in Authentication | yes | https://cwe.mitre.org/data/definitions/304.html |
| cwe_305 | Authentication Bypass by Primary Weakness | yes | https://cwe.mitre.org/data/definitions/305.html |
| cwe_307 | Improper Restriction of Excessive Authentication Attempts | yes | https://cwe.mitre.org/data/definitions/307.html |
| cwe_308 | Use of Single-factor Authentication | yes | https://cwe.mitre.org/data/definitions/308.html |
| cwe_309 | Use of Password System for Primary Authentication | yes | https://cwe.mitre.org/data/definitions/309.html |
| cwe_31 | Path Traversal: 'dir\..\..\filename' | yes | https://cwe.mitre.org/data/definitions/31.html |
| cwe_312 | Cleartext Storage of Sensitive Information | yes | https://cwe.mitre.org/data/definitions/312.html |
| cwe_313 | Cleartext Storage in a File or on Disk | yes | https://cwe.mitre.org/data/definitions/313.html |
| cwe_314 | Cleartext Storage in the Registry | yes | https://cwe.mitre.org/data/definitions/314.html |
| cwe_315 | Cleartext Storage of Sensitive Information in a Cookie | yes | https://cwe.mitre.org/data/definitions/315.html |
| cwe_316 | Cleartext Storage of Sensitive Information in Memory | yes | https://cwe.mitre.org/data/definitions/316.html |
| cwe_317 | Cleartext Storage of Sensitive Information in GUI | yes | https://cwe.mitre.org/data/definitions/317.html |
| cwe_318 | Cleartext Storage of Sensitive Information in Executable | yes | https://cwe.mitre.org/data/definitions/318.html |
| cwe_32 | Path Traversal: '...' (Triple Dot) | yes | https://cwe.mitre.org/data/definitions/32.html |
| cwe_321 | Use of Hard-coded Cryptographic Key | yes | https://cwe.mitre.org/data/definitions/321.html |
| cwe_322 | Key Exchange without Entity Authentication | yes | https://cwe.mitre.org/data/definitions/322.html |
| cwe_323 | Reusing a Nonce, Key Pair in Encryption | yes | https://cwe.mitre.org/data/definitions/323.html |
| cwe_324 | Use of a Key Past its Expiration Date | yes | https://cwe.mitre.org/data/definitions/324.html |
| cwe_325 | Missing Cryptographic Step | yes | https://cwe.mitre.org/data/definitions/325.html |
| cwe_326 | Inadequate Encryption Strength | yes | https://cwe.mitre.org/data/definitions/326.html |
| cwe_328 | Use of Weak Hash | yes | https://cwe.mitre.org/data/definitions/328.html |
| cwe_329 | Generation of Predictable IV with CBC Mode | yes | https://cwe.mitre.org/data/definitions/329.html |
| cwe_33 | Path Traversal: '....' (Multiple Dot) | yes | https://cwe.mitre.org/data/definitions/33.html |
| cwe_330 | Use of Insufficiently Random Values | yes | https://cwe.mitre.org/data/definitions/330.html |
| cwe_331 | Insufficient Entropy | yes | https://cwe.mitre.org/data/definitions/331.html |
| cwe_332 | Insufficient Entropy in PRNG | yes | https://cwe.mitre.org/data/definitions/332.html |
| cwe_333 | Improper Handling of Insufficient Entropy in TRNG | yes | https://cwe.mitre.org/data/definitions/333.html |
| cwe_334 | Small Space of Random Values | yes | https://cwe.mitre.org/data/definitions/334.html |
| cwe_335 | Incorrect Usage of Seeds in Pseudo-Random Number Generator (PRNG) | yes | https://cwe.mitre.org/data/definitions/335.html |
| cwe_336 | Same Seed in Pseudo-Random Number Generator (PRNG) | yes | https://cwe.mitre.org/data/definitions/336.html |
| cwe_337 | Predictable Seed in Pseudo-Random Number Generator (PRNG) | yes | https://cwe.mitre.org/data/definitions/337.html |
| cwe_338 | Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) | yes | https://cwe.mitre.org/data/definitions/338.html |
| cwe_339 | Small Seed Space in PRNG | yes | https://cwe.mitre.org/data/definitions/339.html |
| cwe_34 | Path Traversal: '....//' | yes | https://cwe.mitre.org/data/definitions/34.html |
| cwe_340 | Generation of Predictable Numbers or Identifiers | yes | https://cwe.mitre.org/data/definitions/340.html |
| cwe_341 | Predictable from Observable State | yes | https://cwe.mitre.org/data/definitions/341.html |
| cwe_342 | Predictable Exact Value from Previous Values | yes | https://cwe.mitre.org/data/definitions/342.html |
| cwe_343 | Predictable Value Range from Previous Values | yes | https://cwe.mitre.org/data/definitions/343.html |
| cwe_344 | Use of Invariant Value in Dynamically Changing Context | yes | https://cwe.mitre.org/data/definitions/344.html |
| cwe_348 | Use of Less Trusted Source | yes | https://cwe.mitre.org/data/definitions/348.html |
| cwe_349 | Acceptance of Extraneous Untrusted Data With Trusted Data | yes | https://cwe.mitre.org/data/definitions/349.html |
| cwe_35 | Path Traversal: '.../...//' | yes | https://cwe.mitre.org/data/definitions/35.html |
| cwe_350 | Reliance on Reverse DNS Resolution for a Security-Critical Action | yes | https://cwe.mitre.org/data/definitions/350.html |
| cwe_351 | Insufficient Type Distinction | yes | https://cwe.mitre.org/data/definitions/351.html |
| cwe_353 | Missing Support for Integrity Check | yes | https://cwe.mitre.org/data/definitions/353.html |
| cwe_354 | Improper Validation of Integrity Check Value | yes | https://cwe.mitre.org/data/definitions/354.html |
| cwe_356 | Missing User Interaction for Potentially Unsafe Action | yes | https://cwe.mitre.org/data/definitions/356.html |
| cwe_357 | Insufficient UI Warning of Dangerous Operations | yes | https://cwe.mitre.org/data/definitions/357.html |
| cwe_358 | Improperly Implemented Security Check for Standard | yes | https://cwe.mitre.org/data/definitions/358.html |
| cwe_359 | Exposure of Private Personal Information to an Unauthorized Actor | yes | https://cwe.mitre.org/data/definitions/359.html |
| cwe_36 | Absolute Path Traversal | yes | https://cwe.mitre.org/data/definitions/36.html |
| cwe_360 | Trust of System Event Data | yes | https://cwe.mitre.org/data/definitions/360.html |
| cwe_363 | Race Condition Enabling Link Following | yes | https://cwe.mitre.org/data/definitions/363.html |
| cwe_364 | Signal Handler Race Condition | yes | https://cwe.mitre.org/data/definitions/364.html |
| cwe_365 | DEPRECATED: Race Condition in Switch | no | https://cwe.mitre.org/data/definitions/365.html |
| cwe_366 | Race Condition within a Thread | yes | https://cwe.mitre.org/data/definitions/366.html |
| cwe_367 | Time-of-check Time-of-use (TOCTOU) Race Condition | yes | https://cwe.mitre.org/data/definitions/367.html |
| cwe_368 | Context Switching Race Condition | yes | https://cwe.mitre.org/data/definitions/368.html |
| cwe_369 | Divide By Zero | yes | https://cwe.mitre.org/data/definitions/369.html |
| cwe_37 | Path Traversal: '/absolute/pathname/here' | yes | https://cwe.mitre.org/data/definitions/37.html |
| cwe_370 | Missing Check for Certificate Revocation after Initial Check | yes | https://cwe.mitre.org/data/definitions/370.html |
| cwe_372 | Incomplete Internal State Distinction | yes | https://cwe.mitre.org/data/definitions/372.html |
| cwe_373 | DEPRECATED: State Synchronization Error | no | https://cwe.mitre.org/data/definitions/373.html |
| cwe_374 | Passing Mutable Objects to an Untrusted Method | yes | https://cwe.mitre.org/data/definitions/374.html |
| cwe_375 | Returning a Mutable Object to an Untrusted Caller | yes | https://cwe.mitre.org/data/definitions/375.html |
| cwe_377 | DEPRECATED: Insecure Temporary File | no | https://cwe.mitre.org/data/definitions/377.html |
| cwe_378 | Creation of Temporary File With Insecure Permissions | yes | https://cwe.mitre.org/data/definitions/378.html |
| cwe_379 | Creation of Temporary File in Directory with Insecure Permissions | yes | https://cwe.mitre.org/data/definitions/379.html |
| cwe_38 | Path Traversal: '\absolute\pathname\here' | yes | https://cwe.mitre.org/data/definitions/38.html |
| cwe_382 | J2EE Bad Practices: Use of System.exit() | yes | https://cwe.mitre.org/data/definitions/382.html |
| cwe_383 | J2EE Bad Practices: Direct Use of Threads | yes | https://cwe.mitre.org/data/definitions/383.html |
| cwe_385 | Covert Timing Channel | yes | https://cwe.mitre.org/data/definitions/385.html |
| cwe_386 | Symbolic Name not Mapping to Correct Object | yes | https://cwe.mitre.org/data/definitions/386.html |
| cwe_39 | Path Traversal: 'C:dirname' | yes | https://cwe.mitre.org/data/definitions/39.html |
| cwe_390 | Detection of Error Condition Without Action | yes | https://cwe.mitre.org/data/definitions/390.html |
| cwe_391 | DEPRECATED: Unchecked Error Condition | no | https://cwe.mitre.org/data/definitions/391.html |
| cwe_392 | Missing Report of Error Condition | yes | https://cwe.mitre.org/data/definitions/392.html |
| cwe_393 | Return of Wrong Status Code | yes | https://cwe.mitre.org/data/definitions/393.html |
| cwe_394 | Unexpected Status Code or Return Value | yes | https://cwe.mitre.org/data/definitions/394.html |
| cwe_395 | Use of NullPointerException Catch to Detect NULL Pointer Dereference | yes | https://cwe.mitre.org/data/definitions/395.html |
| cwe_396 | Declaration of Catch for Generic Exception | yes | https://cwe.mitre.org/data/definitions/396.html |
| cwe_397 | Declaration of Throws for Generic Exception | yes | https://cwe.mitre.org/data/definitions/397.html |
| cwe_40 | Path Traversal: '\\UNC\share\name\' (Windows UNC Share) | yes | https://cwe.mitre.org/data/definitions/40.html |
| cwe_401 | Missing Release of Memory after Effective Lifetime | yes | https://cwe.mitre.org/data/definitions/401.html |
| cwe_402 | Transmission of Private Resources into a New Sphere | yes | https://cwe.mitre.org/data/definitions/402.html |
| cwe_403 | Exposure of File Descriptor to Unintended Control Sphere | yes | https://cwe.mitre.org/data/definitions/403.html |
| cwe_404 | Improper Resource Shutdown or Release | yes | https://cwe.mitre.org/data/definitions/404.html |
| cwe_405 | Asymmetric Resource Consumption (Amplification) | yes | https://cwe.mitre.org/data/definitions/405.html |
| cwe_406 | Insufficient Control of Network Message Volume (Network Amplification) | yes | https://cwe.mitre.org/data/definitions/406.html |
| cwe_407 | Inefficient Algorithmic Complexity | yes | https://cwe.mitre.org/data/definitions/407.html |
| cwe_408 | Incorrect Behavior Order: Early Amplification | yes | https://cwe.mitre.org/data/definitions/408.html |
| cwe_409 | Improper Handling of Highly Compressed Data (Data Amplification) | yes | https://cwe.mitre.org/data/definitions/409.html |
| cwe_41 | Improper Resolution of Path Equivalence | yes | https://cwe.mitre.org/data/definitions/41.html |
| cwe_410 | Insufficient Resource Pool | yes | https://cwe.mitre.org/data/definitions/410.html |
| cwe_412 | Unrestricted Externally Accessible Lock | yes | https://cwe.mitre.org/data/definitions/412.html |
| cwe_413 | Improper Resource Locking | yes | https://cwe.mitre.org/data/definitions/413.html |
| cwe_414 | Missing Lock Check | yes | https://cwe.mitre.org/data/definitions/414.html |
| cwe_415 | Double Free | yes | https://cwe.mitre.org/data/definitions/415.html |
| cwe_419 | Unprotected Primary Channel | yes | https://cwe.mitre.org/data/definitions/419.html |
| cwe_42 | Path Equivalence: 'filename.' (Trailing Dot) | yes | https://cwe.mitre.org/data/definitions/42.html |
| cwe_420 | Unprotected Alternate Channel | yes | https://cwe.mitre.org/data/definitions/420.html |
| cwe_421 | Race Condition During Access to Alternate Channel | yes | https://cwe.mitre.org/data/definitions/421.html |
| cwe_422 | Unprotected Windows Messaging Channel | yes | https://cwe.mitre.org/data/definitions/422.html |
| cwe_423 | DEPRECATED: Proxied Trusted Channel | no | https://cwe.mitre.org/data/definitions/423.html |
| cwe_424 | Improper Protection of Alternate Path | yes | https://cwe.mitre.org/data/definitions/424.html |
| cwe_425 | Direct Request | yes | https://cwe.mitre.org/data/definitions/425.html |
| cwe_426 | Untrusted Search Path | yes | https://cwe.mitre.org/data/definitions/426.html |
| cwe_427 | Uncontrolled Search Path Element | yes | https://cwe.mitre.org/data/definitions/427.html |
| cwe_428 | Unquoted Search Path or Element | yes | https://cwe.mitre.org/data/definitions/428.html |
| cwe_43 | Path Equivalence: 'filename....' (Multiple Trailing Dot) | yes | https://cwe.mitre.org/data/definitions/43.html |
| cwe_430 | Deployment of Wrong Handler | yes | https://cwe.mitre.org/data/definitions/430.html |
| cwe_431 | Missing Handler | yes | https://cwe.mitre.org/data/definitions/431.html |
| cwe_432 | Dangerous Signal Handler not Disabled During Sensitive Operations | yes | https://cwe.mitre.org/data/definitions/432.html |
| cwe_433 | Unparsed Raw Web Content Delivery | yes | https://cwe.mitre.org/data/definitions/433.html |
| cwe_435 | Improper Interaction Between Multiple Correctly-Behaving Entities | no | https://cwe.mitre.org/data/definitions/435.html |
| cwe_436 | Interpretation Conflict | yes | https://cwe.mitre.org/data/definitions/436.html |
| cwe_437 | Incomplete Model of Endpoint Features | yes | https://cwe.mitre.org/data/definitions/437.html |
| cwe_439 | Behavioral Change in New Version or Environment | yes | https://cwe.mitre.org/data/definitions/439.html |
| cwe_44 | Path Equivalence: 'file.name' (Internal Dot) | yes | https://cwe.mitre.org/data/definitions/44.html |
| cwe_440 | Expected Behavior Violation | yes | https://cwe.mitre.org/data/definitions/440.html |
| cwe_441 | Unintended Proxy or Intermediary | yes | https://cwe.mitre.org/data/definitions/441.html |
| cwe_443 | DEPRECATED: HTTP response splitting | no | https://cwe.mitre.org/data/definitions/443.html |
| cwe_446 | UI Discrepancy for Security Feature | yes | https://cwe.mitre.org/data/definitions/446.html |
| cwe_447 | Unimplemented or Unsupported Feature in UI | yes | https://cwe.mitre.org/data/definitions/447.html |
| cwe_448 | Obsolete Feature in UI | yes | https://cwe.mitre.org/data/definitions/448.html |
| cwe_449 | The UI Performs the Wrong Action | yes | https://cwe.mitre.org/data/definitions/449.html |
| cwe_45 | Path Equivalence: 'file...name' (Multiple Internal Dot) | yes | https://cwe.mitre.org/data/definitions/45.html |
| cwe_450 | Multiple Interpretations of UI Input | yes | https://cwe.mitre.org/data/definitions/450.html |
| cwe_451 | User Interface (UI) Misrepresentation of Critical Information | yes | https://cwe.mitre.org/data/definitions/451.html |
| cwe_453 | Insecure Default Variable Initialization | yes | https://cwe.mitre.org/data/definitions/453.html |
| cwe_454 | External Initialization of Trusted Variables or Data Stores | yes | https://cwe.mitre.org/data/definitions/454.html |
| cwe_455 | Non-exit on Failed Initialization | yes | https://cwe.mitre.org/data/definitions/455.html |
| cwe_456 | Missing Initialization of a Variable | yes | https://cwe.mitre.org/data/definitions/456.html |
| cwe_457 | Use of Uninitialized Variable | yes | https://cwe.mitre.org/data/definitions/457.html |
| cwe_458 | DEPRECATED: Incorrect Initialization | no | https://cwe.mitre.org/data/definitions/458.html |
| cwe_459 | Incomplete Cleanup | yes | https://cwe.mitre.org/data/definitions/459.html |
| cwe_46 | Path Equivalence: 'filename ' (Trailing Space) | yes | https://cwe.mitre.org/data/definitions/46.html |
| cwe_460 | Improper Cleanup on Thrown Exception | yes | https://cwe.mitre.org/data/definitions/460.html |
| cwe_462 | Duplicate Key in Associative List (Alist) | yes | https://cwe.mitre.org/data/definitions/462.html |
| cwe_463 | Deletion of Data Structure Sentinel | yes | https://cwe.mitre.org/data/definitions/463.html |
| cwe_464 | Addition of Data Structure Sentinel | yes | https://cwe.mitre.org/data/definitions/464.html |
| cwe_466 | Return of Pointer Value Outside of Expected Range | yes | https://cwe.mitre.org/data/definitions/466.html |
| cwe_467 | Use of sizeof() on a Pointer Type | yes | https://cwe.mitre.org/data/definitions/467.html |
| cwe_468 | Incorrect Pointer Scaling | yes | https://cwe.mitre.org/data/definitions/468.html |
| cwe_469 | Use of Pointer Subtraction to Determine Size | yes | https://cwe.mitre.org/data/definitions/469.html |
| cwe_47 | Path Equivalence: ' filename' (Leading Space) | yes | https://cwe.mitre.org/data/definitions/47.html |
| cwe_470 | Use of Externally-Controlled Input to Select Classes or Code | yes | https://cwe.mitre.org/data/definitions/470.html |
| cwe_471 | Modification of Assumed-Immutable Data (MAID) | yes | https://cwe.mitre.org/data/definitions/471.html |
| cwe_472 | External Control of Assumed-Immutable Web Parameter | yes | https://cwe.mitre.org/data/definitions/472.html |
| cwe_473 | PHP External Variable Modification | yes | https://cwe.mitre.org/data/definitions/473.html |
| cwe_474 | Use of Function with Inconsistent Implementations | yes | https://cwe.mitre.org/data/definitions/474.html |
| cwe_475 | Undefined Behavior for Input to API | yes | https://cwe.mitre.org/data/definitions/475.html |
| cwe_476 | NULL Pointer Dereference | yes | https://cwe.mitre.org/data/definitions/476.html |
| cwe_477 | Use of Obsolete Function | yes | https://cwe.mitre.org/data/definitions/477.html |
| cwe_478 | Missing Default Case in Multiple Condition Expression | yes | https://cwe.mitre.org/data/definitions/478.html |
| cwe_479 | Signal Handler Use of a Non-reentrant Function | yes | https://cwe.mitre.org/data/definitions/479.html |
| cwe_48 | Path Equivalence: 'file name' (Internal Whitespace) | yes | https://cwe.mitre.org/data/definitions/48.html |
| cwe_480 | Use of Incorrect Operator | yes | https://cwe.mitre.org/data/definitions/480.html |
| cwe_481 | Assigning instead of Comparing | yes | https://cwe.mitre.org/data/definitions/481.html |
| cwe_482 | Comparing instead of Assigning | yes | https://cwe.mitre.org/data/definitions/482.html |
| cwe_483 | Incorrect Block Delimitation | yes | https://cwe.mitre.org/data/definitions/483.html |
| cwe_484 | Omitted Break Statement in Switch | yes | https://cwe.mitre.org/data/definitions/484.html |
| cwe_486 | Comparison of Classes by Name | yes | https://cwe.mitre.org/data/definitions/486.html |
| cwe_487 | Reliance on Package-level Scope | yes | https://cwe.mitre.org/data/definitions/487.html |
| cwe_488 | Exposure of Data Element to Wrong Session | yes | https://cwe.mitre.org/data/definitions/488.html |
| cwe_489 | Active Debug Code | yes | https://cwe.mitre.org/data/definitions/489.html |
| cwe_49 | Path Equivalence: 'filename/' (Trailing Slash) | yes | https://cwe.mitre.org/data/definitions/49.html |
| cwe_491 | Public cloneable() Method Without Final | yes | https://cwe.mitre.org/data/definitions/491.html |
| cwe_492 | Use of Inner Class Containing Sensitive Data | yes | https://cwe.mitre.org/data/definitions/492.html |
| cwe_493 | Critical Public Variable Without Final Modifier | yes | https://cwe.mitre.org/data/definitions/493.html |
| cwe_494 | Download of Code Without Integrity Check | yes | https://cwe.mitre.org/data/definitions/494.html |
| cwe_495 | Private Data Structure Returned From A Public Method | yes | https://cwe.mitre.org/data/definitions/495.html |
| cwe_496 | Public Data Assigned to Private Array-Typed Field | yes | https://cwe.mitre.org/data/definitions/496.html |
| cwe_497 | Exposure of Sensitive System Information to an Unauthorized Control Sphere | yes | https://cwe.mitre.org/data/definitions/497.html |
| cwe_498 | Cloneable Class Containing Sensitive Information | yes | https://cwe.mitre.org/data/definitions/498.html |
| cwe_499 | Serializable Class Containing Sensitive Data | yes | https://cwe.mitre.org/data/definitions/499.html |
| cwe_5 | J2EE Misconfiguration: Data Transmission Without Encryption | yes | https://cwe.mitre.org/data/definitions/5.html |
| cwe_50 | Path Equivalence: '//multiple/leading/slash' | yes | https://cwe.mitre.org/data/definitions/50.html |
| cwe_500 | Public Static Field Not Marked Final | yes | https://cwe.mitre.org/data/definitions/500.html |
| cwe_501 | Trust Boundary Violation | yes | https://cwe.mitre.org/data/definitions/501.html |
| cwe_506 | Embedded Malicious Code | yes | https://cwe.mitre.org/data/definitions/506.html |
| cwe_507 | Trojan Horse | yes | https://cwe.mitre.org/data/definitions/507.html |
| cwe_508 | Non-Replicating Malicious Code | yes | https://cwe.mitre.org/data/definitions/508.html |
| cwe_509 | Replicating Malicious Code (Virus or Worm) | yes | https://cwe.mitre.org/data/definitions/509.html |
| cwe_51 | Path Equivalence: '/multiple//internal/slash' | yes | https://cwe.mitre.org/data/definitions/51.html |
| cwe_510 | Trapdoor | yes | https://cwe.mitre.org/data/definitions/510.html |
| cwe_511 | Logic/Time Bomb | yes | https://cwe.mitre.org/data/definitions/511.html |
| cwe_512 | Spyware | yes | https://cwe.mitre.org/data/definitions/512.html |
| cwe_514 | Covert Channel | yes | https://cwe.mitre.org/data/definitions/514.html |
| cwe_515 | Covert Storage Channel | yes | https://cwe.mitre.org/data/definitions/515.html |
| cwe_516 | DEPRECATED: Covert Timing Channel | no | https://cwe.mitre.org/data/definitions/516.html |
| cwe_52 | Path Equivalence: '/multiple/trailing/slash//' | yes | https://cwe.mitre.org/data/definitions/52.html |
| cwe_520 | .NET Misconfiguration: Use of Impersonation | yes | https://cwe.mitre.org/data/definitions/520.html |
| cwe_521 | Weak Password Requirements | yes | https://cwe.mitre.org/data/definitions/521.html |
| cwe_522 | Insufficiently Protected Credentials | yes | https://cwe.mitre.org/data/definitions/522.html |
| cwe_523 | Unprotected Transport of Credentials | yes | https://cwe.mitre.org/data/definitions/523.html |
| cwe_524 | Use of Cache Containing Sensitive Information | yes | https://cwe.mitre.org/data/definitions/524.html |
| cwe_525 | Use of Web Browser Cache Containing Sensitive Information | yes | https://cwe.mitre.org/data/definitions/525.html |
| cwe_526 | Cleartext Storage of Sensitive Information in an Environment Variable | yes | https://cwe.mitre.org/data/definitions/526.html |
| cwe_527 | Exposure of Version-Control Repository to an Unauthorized Control Sphere | yes | https://cwe.mitre.org/data/definitions/527.html |
| cwe_528 | Exposure of Core Dump File to an Unauthorized Control Sphere | yes | https://cwe.mitre.org/data/definitions/528.html |
| cwe_529 | Exposure of Access Control List Files to an Unauthorized Control Sphere | yes | https://cwe.mitre.org/data/definitions/529.html |
| cwe_53 | Path Equivalence: '\multiple\\internal\backslash' | yes | https://cwe.mitre.org/data/definitions/53.html |
| cwe_530 | Exposure of Backup File to an Unauthorized Control Sphere | yes | https://cwe.mitre.org/data/definitions/530.html |
| cwe_531 | Inclusion of Sensitive Information in Test Code | yes | https://cwe.mitre.org/data/definitions/531.html |
| cwe_533 | DEPRECATED: Information Exposure Through Server Log Files | no | https://cwe.mitre.org/data/definitions/533.html |
| cwe_534 | DEPRECATED: Information Exposure Through Debug Log Files | no | https://cwe.mitre.org/data/definitions/534.html |
| cwe_535 | Exposure of Information Through Shell Error Message | yes | https://cwe.mitre.org/data/definitions/535.html |
| cwe_536 | Servlet Runtime Error Message Containing Sensitive Information | yes | https://cwe.mitre.org/data/definitions/536.html |
| cwe_537 | Java Runtime Error Message Containing Sensitive Information | yes | https://cwe.mitre.org/data/definitions/537.html |
| cwe_538 | Insertion of Sensitive Information into Externally-Accessible File or Directory | yes | https://cwe.mitre.org/data/definitions/538.html |
| cwe_539 | Use of Persistent Cookies Containing Sensitive Information | yes | https://cwe.mitre.org/data/definitions/539.html |
| cwe_54 | Path Equivalence: 'filedir\' (Trailing Backslash) | yes | https://cwe.mitre.org/data/definitions/54.html |
| cwe_540 | Inclusion of Sensitive Information in Source Code | yes | https://cwe.mitre.org/data/definitions/540.html |
| cwe_541 | Inclusion of Sensitive Information in an Include File | yes | https://cwe.mitre.org/data/definitions/541.html |
| cwe_542 | DEPRECATED: Information Exposure Through Cleanup Log Files | no | https://cwe.mitre.org/data/definitions/542.html |
| cwe_543 | Use of Singleton Pattern Without Synchronization in a Multithreaded Context | yes | https://cwe.mitre.org/data/definitions/543.html |
| cwe_544 | Missing Standardized Error Handling Mechanism | yes | https://cwe.mitre.org/data/definitions/544.html |
| cwe_545 | DEPRECATED: Use of Dynamic Class Loading | no | https://cwe.mitre.org/data/definitions/545.html |
| cwe_546 | Suspicious Comment | yes | https://cwe.mitre.org/data/definitions/546.html |
| cwe_547 | Use of Hard-coded, Security-relevant Constants | yes | https://cwe.mitre.org/data/definitions/547.html |
| cwe_548 | Exposure of Information Through Directory Listing | yes | https://cwe.mitre.org/data/definitions/548.html |
| cwe_549 | Missing Password Field Masking | yes | https://cwe.mitre.org/data/definitions/549.html |
| cwe_55 | Path Equivalence: '/./' (Single Dot Directory) | yes | https://cwe.mitre.org/data/definitions/55.html |
| cwe_550 | Server-generated Error Message Containing Sensitive Information | yes | https://cwe.mitre.org/data/definitions/550.html |
| cwe_551 | Incorrect Behavior Order: Authorization Before Parsing and Canonicalization | yes | https://cwe.mitre.org/data/definitions/551.html |
| cwe_552 | Files or Directories Accessible to External Parties | yes | https://cwe.mitre.org/data/definitions/552.html |
| cwe_553 | Command Shell in Externally Accessible Directory | yes | https://cwe.mitre.org/data/definitions/553.html |
| cwe_554 | ASP.NET Misconfiguration: Not Using Input Validation Framework | yes | https://cwe.mitre.org/data/definitions/554.html |
| cwe_555 | J2EE Misconfiguration: Plaintext Password in Configuration File | yes | https://cwe.mitre.org/data/definitions/555.html |
| cwe_556 | ASP.NET Misconfiguration: Use of Identity Impersonation | yes | https://cwe.mitre.org/data/definitions/556.html |
| cwe_558 | Use of getlogin() in Multithreaded Application | yes | https://cwe.mitre.org/data/definitions/558.html |
| cwe_56 | Path Equivalence: 'filedir*' (Wildcard) | yes | https://cwe.mitre.org/data/definitions/56.html |
| cwe_560 | Use of umask() with chmod-style Argument | yes | https://cwe.mitre.org/data/definitions/560.html |
| cwe_561 | Dead Code | yes | https://cwe.mitre.org/data/definitions/561.html |
| cwe_562 | Return of Stack Variable Address | yes | https://cwe.mitre.org/data/definitions/562.html |
| cwe_563 | Assignment to Variable without Use | yes | https://cwe.mitre.org/data/definitions/563.html |
| cwe_564 | Use of Hibernate with HQL/SQL Query String Containing External Input | yes | https://cwe.mitre.org/data/definitions/564.html |
| cwe_565 | Reliance on Cookies without Validation and Integrity Checking | yes | https://cwe.mitre.org/data/definitions/565.html |
| cwe_566 | Authorization Bypass Through User-Controlled SQL Primary Key | yes | https://cwe.mitre.org/data/definitions/566.html |
| cwe_567 | Unsynchronized Access to Shared Data in a Multithreaded Context | yes | https://cwe.mitre.org/data/definitions/567.html |
| cwe_568 | finalize() Method Without super.finalize() | yes | https://cwe.mitre.org/data/definitions/568.html |
| cwe_57 | Path Equivalence: 'fakedir/../realdir/filename' | yes | https://cwe.mitre.org/data/definitions/57.html |
| cwe_570 | Expression is Always False | yes | https://cwe.mitre.org/data/definitions/570.html |
| cwe_571 | Expression is Always True | yes | https://cwe.mitre.org/data/definitions/571.html |
| cwe_572 | Call to Thread run() instead of start() | yes | https://cwe.mitre.org/data/definitions/572.html |
| cwe_573 | Improper Following of Specification by Caller | yes | https://cwe.mitre.org/data/definitions/573.html |
| cwe_574 | EJB Bad Practices: Use of Synchronization Primitives | yes | https://cwe.mitre.org/data/definitions/574.html |
| cwe_575 | EJB Bad Practices: Use of AWT Swing | yes | https://cwe.mitre.org/data/definitions/575.html |
| cwe_576 | EJB Bad Practices: Use of Java I/O | yes | https://cwe.mitre.org/data/definitions/576.html |
| cwe_577 | EJB Bad Practices: Use of Sockets | yes | https://cwe.mitre.org/data/definitions/577.html |
| cwe_578 | EJB Bad Practices: Use of Class Loader | yes | https://cwe.mitre.org/data/definitions/578.html |
| cwe_579 | J2EE Bad Practices: Non-serializable Object Stored in Session | yes | https://cwe.mitre.org/data/definitions/579.html |
| cwe_58 | Path Equivalence: Windows 8.3 Filename | yes | https://cwe.mitre.org/data/definitions/58.html |
| cwe_580 | clone() Method Without super.clone() | yes | https://cwe.mitre.org/data/definitions/580.html |
| cwe_581 | Object Model Violation: Just One of Equals and Hashcode Defined | yes | https://cwe.mitre.org/data/definitions/581.html |
| cwe_582 | Array Declared Public, Final, and Static | yes | https://cwe.mitre.org/data/definitions/582.html |
| cwe_583 | finalize() Method Declared Public | yes | https://cwe.mitre.org/data/definitions/583.html |
| cwe_584 | Return Inside Finally Block | yes | https://cwe.mitre.org/data/definitions/584.html |
| cwe_585 | Empty Synchronized Block | yes | https://cwe.mitre.org/data/definitions/585.html |
| cwe_586 | Explicit Call to Finalize() | yes | https://cwe.mitre.org/data/definitions/586.html |
| cwe_587 | Assignment of a Fixed Address to a Pointer | yes | https://cwe.mitre.org/data/definitions/587.html |
| cwe_588 | Attempt to Access Child of a Non-structure Pointer | yes | https://cwe.mitre.org/data/definitions/588.html |
| cwe_589 | Call to Non-ubiquitous API | yes | https://cwe.mitre.org/data/definitions/589.html |
| cwe_59 | Improper Link Resolution Before File Access | yes | https://cwe.mitre.org/data/definitions/59.html |
| cwe_590 | Free of Memory not on the Heap | yes | https://cwe.mitre.org/data/definitions/590.html |
| cwe_591 | Sensitive Data Storage in Improperly Locked Memory | yes | https://cwe.mitre.org/data/definitions/591.html |
| cwe_592 | DEPRECATED: Authentication Bypass Issues | no | https://cwe.mitre.org/data/definitions/592.html |
| cwe_593 | Authentication Bypass: OpenSSL CTX Object Modified after SSL Objects are Created | yes | https://cwe.mitre.org/data/definitions/593.html |
| cwe_594 | J2EE Framework: Saving Unserializable Objects to Disk | yes | https://cwe.mitre.org/data/definitions/594.html |
| cwe_595 | Comparison of Object References Instead of Object Contents | yes | https://cwe.mitre.org/data/definitions/595.html |
| cwe_596 | DEPRECATED: Incorrect Semantic Object Comparison | no | https://cwe.mitre.org/data/definitions/596.html |
| cwe_597 | Use of Wrong Operator in String Comparison | yes | https://cwe.mitre.org/data/definitions/597.html |
| cwe_598 | Use of HTTP Request With Sensitive Query String | yes | https://cwe.mitre.org/data/definitions/598.html |
| cwe_599 | Missing Validation of OpenSSL Certificate | yes | https://cwe.mitre.org/data/definitions/599.html |
| cwe_6 | J2EE Misconfiguration: Insufficient Session-ID Length | yes | https://cwe.mitre.org/data/definitions/6.html |
| cwe_600 | Uncaught Exception in Servlet | yes | https://cwe.mitre.org/data/definitions/600.html |
| cwe_602 | Client-Side Enforcement of Server-Side Security | yes | https://cwe.mitre.org/data/definitions/602.html |
| cwe_603 | Use of Client-Side Authentication | yes | https://cwe.mitre.org/data/definitions/603.html |
| cwe_605 | Multiple Binds to the Same Port | yes | https://cwe.mitre.org/data/definitions/605.html |
| cwe_606 | Unchecked Input for Loop Condition | yes | https://cwe.mitre.org/data/definitions/606.html |
| cwe_607 | Public Static Final Field References Mutable Object | yes | https://cwe.mitre.org/data/definitions/607.html |
| cwe_608 | Struts: Non-private Field in ActionForm Class | yes | https://cwe.mitre.org/data/definitions/608.html |
| cwe_609 | Double-Checked Locking | yes | https://cwe.mitre.org/data/definitions/609.html |
| cwe_61 | UNIX Symbolic Link (Symlink) Following | yes | https://cwe.mitre.org/data/definitions/61.html |
| cwe_610 | Externally Controlled Reference to a Resource in Another Sphere | yes | https://cwe.mitre.org/data/definitions/610.html |
| cwe_612 | Improper Authorization of Index Containing Sensitive Information | yes | https://cwe.mitre.org/data/definitions/612.html |
| cwe_615 | Inclusion of Sensitive Information in Source Code Comments | yes | https://cwe.mitre.org/data/definitions/615.html |
| cwe_616 | Incomplete Identification of Uploaded File Variables (PHP) | yes | https://cwe.mitre.org/data/definitions/616.html |
| cwe_617 | Reachable Assertion | yes | https://cwe.mitre.org/data/definitions/617.html |
| cwe_618 | Exposed Unsafe ActiveX Method | yes | https://cwe.mitre.org/data/definitions/618.html |
| cwe_619 | Dangling Database Cursor | yes | https://cwe.mitre.org/data/definitions/619.html |
| cwe_62 | UNIX Hard Link | yes | https://cwe.mitre.org/data/definitions/62.html |
| cwe_620 | Unverified Password Change | yes | https://cwe.mitre.org/data/definitions/620.html |
| cwe_621 | Variable Extraction Error | yes | https://cwe.mitre.org/data/definitions/621.html |
| cwe_622 | Improper Validation of Function Hook Arguments | yes | https://cwe.mitre.org/data/definitions/622.html |
| cwe_623 | Unsafe ActiveX Control Marked Safe For Scripting | yes | https://cwe.mitre.org/data/definitions/623.html |
| cwe_624 | Executable Regular Expression Error | yes | https://cwe.mitre.org/data/definitions/624.html |
| cwe_625 | Permissive Regular Expression | yes | https://cwe.mitre.org/data/definitions/625.html |
| cwe_626 | Null Byte Interaction Error (Poison Null Byte) | yes | https://cwe.mitre.org/data/definitions/626.html |
| cwe_627 | Dynamic Variable Evaluation | yes | https://cwe.mitre.org/data/definitions/627.html |
| cwe_628 | Function Call with Incorrectly Specified Arguments | yes | https://cwe.mitre.org/data/definitions/628.html |
| cwe_636 | Not Failing Securely | yes | https://cwe.mitre.org/data/definitions/636.html |
| cwe_637 | Unnecessary Complexity in Protection Mechanism (Not Using 'Economy of Mechanism') | yes | https://cwe.mitre.org/data/definitions/637.html |
| cwe_638 | Not Using Complete Mediation | yes | https://cwe.mitre.org/data/definitions/638.html |
| cwe_64 | Windows Shortcut Following (.LNK) | yes | https://cwe.mitre.org/data/definitions/64.html |
| cwe_640 | Weak Password Recovery Mechanism for Forgotten Password | yes | https://cwe.mitre.org/data/definitions/640.html |
| cwe_641 | Improper Restriction of Names for Files and Other Resources | yes | https://cwe.mitre.org/data/definitions/641.html |
| cwe_642 | External Control of Critical State Data | yes | https://cwe.mitre.org/data/definitions/642.html |
| cwe_643 | Improper Neutralization of Data within XPath Expressions | yes | https://cwe.mitre.org/data/definitions/643.html |
| cwe_644 | Improper Neutralization of HTTP Headers for Scripting Syntax | yes | https://cwe.mitre.org/data/definitions/644.html |
| cwe_645 | Overly Restrictive Account Lockout Mechanism | yes | https://cwe.mitre.org/data/definitions/645.html |
| cwe_646 | Reliance on File Name or Extension of Externally-Supplied File | yes | https://cwe.mitre.org/data/definitions/646.html |
| cwe_647 | Use of Non-Canonical URL Paths for Authorization Decisions | yes | https://cwe.mitre.org/data/definitions/647.html |
| cwe_648 | Incorrect Use of Privileged APIs | yes | https://cwe.mitre.org/data/definitions/648.html |
| cwe_649 | Reliance on Obfuscation or Encryption of Security-Relevant Inputs without Integrity Checking | yes | https://cwe.mitre.org/data/definitions/649.html |
| cwe_65 | Windows Hard Link | yes | https://cwe.mitre.org/data/definitions/65.html |
| cwe_650 | Trusting HTTP Permission Methods on the Server Side | yes | https://cwe.mitre.org/data/definitions/650.html |
| cwe_651 | Exposure of WSDL File Containing Sensitive Information | yes | https://cwe.mitre.org/data/definitions/651.html |
| cwe_652 | Improper Neutralization of Data within XQuery Expressions | yes | https://cwe.mitre.org/data/definitions/652.html |
| cwe_653 | Improper Isolation or Compartmentalization | yes | https://cwe.mitre.org/data/definitions/653.html |
| cwe_654 | Reliance on a Single Factor in a Security Decision | yes | https://cwe.mitre.org/data/definitions/654.html |
| cwe_655 | Insufficient Psychological Acceptability | yes | https://cwe.mitre.org/data/definitions/655.html |
| cwe_656 | Reliance on Security Through Obscurity | yes | https://cwe.mitre.org/data/definitions/656.html |
| cwe_657 | Violation of Secure Design Principles | yes | https://cwe.mitre.org/data/definitions/657.html |
| cwe_66 | Improper Handling of File Names that Identify Virtual Resources | yes | https://cwe.mitre.org/data/definitions/66.html |
| cwe_662 | Improper Synchronization | yes | https://cwe.mitre.org/data/definitions/662.html |
| cwe_663 | Use of a Non-reentrant Function in a Concurrent Context | yes | https://cwe.mitre.org/data/definitions/663.html |
| cwe_664 | Improper Control of a Resource Through its Lifetime | no | https://cwe.mitre.org/data/definitions/664.html |
| cwe_665 | Improper Initialization | yes | https://cwe.mitre.org/data/definitions/665.html |
| cwe_666 | Operation on Resource in Wrong Phase of Lifetime | yes | https://cwe.mitre.org/data/definitions/666.html |
| cwe_667 | Improper Locking | yes | https://cwe.mitre.org/data/definitions/667.html |
| cwe_668 | Exposure of Resource to Wrong Sphere | yes | https://cwe.mitre.org/data/definitions/668.html |
| cwe_669 | Incorrect Resource Transfer Between Spheres | yes | https://cwe.mitre.org/data/definitions/669.html |
| cwe_67 | Improper Handling of Windows Device Names | yes | https://cwe.mitre.org/data/definitions/67.html |
| cwe_670 | Always-Incorrect Control Flow Implementation | yes | https://cwe.mitre.org/data/definitions/670.html |
| cwe_671 | Lack of Administrator Control over Security | yes | https://cwe.mitre.org/data/definitions/671.html |
| cwe_672 | Operation on a Resource after Expiration or Release | yes | https://cwe.mitre.org/data/definitions/672.html |
| cwe_673 | External Influence of Sphere Definition | yes | https://cwe.mitre.org/data/definitions/673.html |
| cwe_674 | Uncontrolled Recursion | yes | https://cwe.mitre.org/data/definitions/674.html |
| cwe_675 | Multiple Operations on Resource in Single-Operation Context | yes | https://cwe.mitre.org/data/definitions/675.html |
| cwe_676 | Use of Potentially Dangerous Function | yes | https://cwe.mitre.org/data/definitions/676.html |
| cwe_680 | Integer Overflow to Buffer Overflow | yes | https://cwe.mitre.org/data/definitions/680.html |
| cwe_681 | Incorrect Conversion between Numeric Types | yes | https://cwe.mitre.org/data/definitions/681.html |
| cwe_682 | Incorrect Calculation | no | https://cwe.mitre.org/data/definitions/682.html |
| cwe_683 | Function Call With Incorrect Order of Arguments | yes | https://cwe.mitre.org/data/definitions/683.html |
| cwe_684 | Incorrect Provision of Specified Functionality | yes | https://cwe.mitre.org/data/definitions/684.html |
| cwe_685 | Function Call With Incorrect Number of Arguments | yes | https://cwe.mitre.org/data/definitions/685.html |
| cwe_686 | Function Call With Incorrect Argument Type | yes | https://cwe.mitre.org/data/definitions/686.html |
| cwe_687 | Function Call With Incorrectly Specified Argument Value | yes | https://cwe.mitre.org/data/definitions/687.html |
| cwe_688 | Function Call With Incorrect Variable or Reference as Argument | yes | https://cwe.mitre.org/data/definitions/688.html |
| cwe_689 | Permission Race Condition During Resource Copy | yes | https://cwe.mitre.org/data/definitions/689.html |
| cwe_69 | Improper Handling of Windows ::DATA Alternate Data Stream | yes | https://cwe.mitre.org/data/definitions/69.html |
| cwe_690 | Unchecked Return Value to NULL Pointer Dereference | yes | https://cwe.mitre.org/data/definitions/690.html |
| cwe_691 | Insufficient Control Flow Management | no | https://cwe.mitre.org/data/definitions/691.html |
| cwe_692 | Incomplete Denylist to Cross-Site Scripting | yes | https://cwe.mitre.org/data/definitions/692.html |
| cwe_693 | Protection Mechanism Failure | no | https://cwe.mitre.org/data/definitions/693.html |
| cwe_694 | Use of Multiple Resources with Duplicate Identifier | yes | https://cwe.mitre.org/data/definitions/694.html |
| cwe_695 | Use of Low-Level Functionality | yes | https://cwe.mitre.org/data/definitions/695.html |
| cwe_696 | Incorrect Behavior Order | yes | https://cwe.mitre.org/data/definitions/696.html |
| cwe_697 | Incorrect Comparison | no | https://cwe.mitre.org/data/definitions/697.html |
| cwe_698 | Execution After Redirect (EAR) | yes | https://cwe.mitre.org/data/definitions/698.html |
| cwe_7 | J2EE Misconfiguration: Missing Custom Error Page | yes | https://cwe.mitre.org/data/definitions/7.html |
| cwe_703 | Improper Check or Handling of Exceptional Conditions | no | https://cwe.mitre.org/data/definitions/703.html |
| cwe_704 | Incorrect Type Conversion or Cast | yes | https://cwe.mitre.org/data/definitions/704.html |
| cwe_705 | Incorrect Control Flow Scoping | yes | https://cwe.mitre.org/data/definitions/705.html |
| cwe_706 | Use of Incorrectly-Resolved Name or Reference | yes | https://cwe.mitre.org/data/definitions/706.html |
| cwe_707 | Improper Neutralization | no | https://cwe.mitre.org/data/definitions/707.html |
| cwe_708 | Incorrect Ownership Assignment | yes | https://cwe.mitre.org/data/definitions/708.html |
| cwe_71 | DEPRECATED: Apple '.DS_Store' | no | https://cwe.mitre.org/data/definitions/71.html |
| cwe_710 | Improper Adherence to Coding Standards | no | https://cwe.mitre.org/data/definitions/710.html |
| cwe_72 | Improper Handling of Apple HFS+ Alternate Data Stream Path | yes | https://cwe.mitre.org/data/definitions/72.html |
| cwe_73 | External Control of File Name or Path | yes | https://cwe.mitre.org/data/definitions/73.html |
| cwe_733 | Compiler Optimization Removal or Modification of Security-critical Code | yes | https://cwe.mitre.org/data/definitions/733.html |
| cwe_749 | Exposed Dangerous Method or Function | yes | https://cwe.mitre.org/data/definitions/749.html |
| cwe_75 | Failure to Sanitize Special Elements into a Different Plane | yes | https://cwe.mitre.org/data/definitions/75.html |
| cwe_754 | Improper Check for Unusual or Exceptional Conditions | yes | https://cwe.mitre.org/data/definitions/754.html |
| cwe_755 | Improper Handling of Exceptional Conditions | yes | https://cwe.mitre.org/data/definitions/755.html |
| cwe_756 | Missing Custom Error Page | yes | https://cwe.mitre.org/data/definitions/756.html |
| cwe_757 | Selection of Less-Secure Algorithm During Negotiation | yes | https://cwe.mitre.org/data/definitions/757.html |
| cwe_758 | Reliance on Undefined, Unspecified, or Implementation-Defined Behavior | yes | https://cwe.mitre.org/data/definitions/758.html |
| cwe_759 | Use of a One-Way Hash without a Salt | yes | https://cwe.mitre.org/data/definitions/759.html |
| cwe_76 | Improper Neutralization of Equivalent Special Elements | yes | https://cwe.mitre.org/data/definitions/76.html |
| cwe_760 | Use of a One-Way Hash with a Predictable Salt | yes | https://cwe.mitre.org/data/definitions/760.html |
| cwe_761 | Free of Pointer not at Start of Buffer | yes | https://cwe.mitre.org/data/definitions/761.html |
| cwe_762 | Mismatched Memory Management Routines | yes | https://cwe.mitre.org/data/definitions/762.html |
| cwe_763 | Release of Invalid Pointer or Reference | yes | https://cwe.mitre.org/data/definitions/763.html |
| cwe_764 | Multiple Locks of a Critical Resource | yes | https://cwe.mitre.org/data/definitions/764.html |
| cwe_765 | Multiple Unlocks of a Critical Resource | yes | https://cwe.mitre.org/data/definitions/765.html |
| cwe_766 | Critical Data Element Declared Public | yes | https://cwe.mitre.org/data/definitions/766.html |
| cwe_767 | Access to Critical Private Variable via Public Method | yes | https://cwe.mitre.org/data/definitions/767.html |
| cwe_768 | Incorrect Short Circuit Evaluation | yes | https://cwe.mitre.org/data/definitions/768.html |
| cwe_769 | DEPRECATED: Uncontrolled File Descriptor Consumption | no | https://cwe.mitre.org/data/definitions/769.html |
| cwe_77 | Improper Neutralization of Special Elements used in a Command | yes | https://cwe.mitre.org/data/definitions/77.html |
| cwe_771 | Missing Reference to Active Allocated Resource | yes | https://cwe.mitre.org/data/definitions/771.html |
| cwe_772 | Missing Release of Resource after Effective Lifetime | yes | https://cwe.mitre.org/data/definitions/772.html |
| cwe_773 | Missing Reference to Active File Descriptor or Handle | yes | https://cwe.mitre.org/data/definitions/773.html |
| cwe_774 | Allocation of File Descriptors or Handles Without Limits or Throttling | yes | https://cwe.mitre.org/data/definitions/774.html |
| cwe_775 | Missing Release of File Descriptor or Handle after Effective Lifetime | yes | https://cwe.mitre.org/data/definitions/775.html |
| cwe_776 | Improper Restriction of Recursive Entity References in DTDs | yes | https://cwe.mitre.org/data/definitions/776.html |
| cwe_777 | Regular Expression without Anchors | yes | https://cwe.mitre.org/data/definitions/777.html |
| cwe_778 | Insufficient Logging | yes | https://cwe.mitre.org/data/definitions/778.html |
| cwe_779 | Logging of Excessive Data | yes | https://cwe.mitre.org/data/definitions/779.html |
| cwe_780 | Use of RSA Algorithm without OAEP | yes | https://cwe.mitre.org/data/definitions/780.html |
| cwe_781 | Improper Address Validation in IOCTL with METHOD_NEITHER I/O Control Code | yes | https://cwe.mitre.org/data/definitions/781.html |
| cwe_782 | Exposed IOCTL with Insufficient Access Control | yes | https://cwe.mitre.org/data/definitions/782.html |
| cwe_783 | Operator Precedence Logic Error | yes | https://cwe.mitre.org/data/definitions/783.html |
| cwe_784 | Reliance on Cookies without Validation and Integrity Checking in a Security Decision | yes | https://cwe.mitre.org/data/definitions/784.html |
| cwe_785 | Use of Path Manipulation Function without Maximum-sized Buffer | yes | https://cwe.mitre.org/data/definitions/785.html |
| cwe_786 | Access of Memory Location Before Start of Buffer | yes | https://cwe.mitre.org/data/definitions/786.html |
| cwe_788 | Access of Memory Location After End of Buffer | yes | https://cwe.mitre.org/data/definitions/788.html |
| cwe_789 | Memory Allocation with Excessive Size Value | yes | https://cwe.mitre.org/data/definitions/789.html |
| cwe_790 | Improper Filtering of Special Elements | yes | https://cwe.mitre.org/data/definitions/790.html |
| cwe_791 | Incomplete Filtering of Special Elements | yes | https://cwe.mitre.org/data/definitions/791.html |
| cwe_792 | Incomplete Filtering of One or More Instances of Special Elements | yes | https://cwe.mitre.org/data/definitions/792.html |
| cwe_793 | Only Filtering One Instance of a Special Element | yes | https://cwe.mitre.org/data/definitions/793.html |
| cwe_794 | Incomplete Filtering of Multiple Instances of Special Elements | yes | https://cwe.mitre.org/data/definitions/794.html |
| cwe_795 | Only Filtering Special Elements at a Specified Location | yes | https://cwe.mitre.org/data/definitions/795.html |
| cwe_796 | Only Filtering Special Elements Relative to a Marker | yes | https://cwe.mitre.org/data/definitions/796.html |
| cwe_797 | Only Filtering Special Elements at an Absolute Position | yes | https://cwe.mitre.org/data/definitions/797.html |
| cwe_8 | J2EE Misconfiguration: Entity Bean Declared Remote | yes | https://cwe.mitre.org/data/definitions/8.html |
| cwe_80 | Improper Neutralization of Script-Related HTML Tags in a Web Page | yes | https://cwe.mitre.org/data/definitions/80.html |
| cwe_804 | Guessable CAPTCHA | yes | https://cwe.mitre.org/data/definitions/804.html |
| cwe_805 | Buffer Access with Incorrect Length Value | yes | https://cwe.mitre.org/data/definitions/805.html |
| cwe_806 | Buffer Access Using Size of Source Buffer | yes | https://cwe.mitre.org/data/definitions/806.html |
| cwe_807 | Reliance on Untrusted Inputs in a Security Decision | yes | https://cwe.mitre.org/data/definitions/807.html |
| cwe_81 | Improper Neutralization of Script in an Error Message Web Page | yes | https://cwe.mitre.org/data/definitions/81.html |
| cwe_82 | Improper Neutralization of Script in Attributes of IMG Tags in a Web Page | yes | https://cwe.mitre.org/data/definitions/82.html |
| cwe_820 | Missing Synchronization | yes | https://cwe.mitre.org/data/definitions/820.html |
| cwe_821 | Incorrect Synchronization | yes | https://cwe.mitre.org/data/definitions/821.html |
| cwe_822 | Untrusted Pointer Dereference | yes | https://cwe.mitre.org/data/definitions/822.html |
| cwe_823 | Use of Out-of-range Pointer Offset | yes | https://cwe.mitre.org/data/definitions/823.html |
| cwe_824 | Access of Uninitialized Pointer | yes | https://cwe.mitre.org/data/definitions/824.html |
| cwe_825 | Expired Pointer Dereference | yes | https://cwe.mitre.org/data/definitions/825.html |
| cwe_826 | Premature Release of Resource During Expected Lifetime | yes | https://cwe.mitre.org/data/definitions/826.html |
| cwe_827 | Improper Control of Document Type Definition | yes | https://cwe.mitre.org/data/definitions/827.html |
| cwe_828 | Signal Handler with Functionality that is not Asynchronous-Safe | yes | https://cwe.mitre.org/data/definitions/828.html |
| cwe_829 | Inclusion of Functionality from Untrusted Control Sphere | yes | https://cwe.mitre.org/data/definitions/829.html |
| cwe_83 | Improper Neutralization of Script in Attributes in a Web Page | yes | https://cwe.mitre.org/data/definitions/83.html |
| cwe_830 | Inclusion of Web Functionality from an Untrusted Source | yes | https://cwe.mitre.org/data/definitions/830.html |
| cwe_831 | Signal Handler Function Associated with Multiple Signals | yes | https://cwe.mitre.org/data/definitions/831.html |
| cwe_832 | Unlock of a Resource that is not Locked | yes | https://cwe.mitre.org/data/definitions/832.html |
| cwe_833 | Deadlock | yes | https://cwe.mitre.org/data/definitions/833.html |
| cwe_834 | Excessive Iteration | yes | https://cwe.mitre.org/data/definitions/834.html |
| cwe_835 | Loop with Unreachable Exit Condition | yes | https://cwe.mitre.org/data/definitions/835.html |
| cwe_836 | Use of Password Hash Instead of Password for Authentication | yes | https://cwe.mitre.org/data/definitions/836.html |
| cwe_837 | Improper Enforcement of a Single, Unique Action | yes | https://cwe.mitre.org/data/definitions/837.html |
| cwe_838 | Inappropriate Encoding for Output Context | yes | https://cwe.mitre.org/data/definitions/838.html |
| cwe_839 | Numeric Range Comparison Without Minimum Check | yes | https://cwe.mitre.org/data/definitions/839.html |
| cwe_84 | Improper Neutralization of Encoded URI Schemes in a Web Page | yes | https://cwe.mitre.org/data/definitions/84.html |
| cwe_842 | Placement of User into Incorrect Group | yes | https://cwe.mitre.org/data/definitions/842.html |
| cwe_843 | Access of Resource Using Incompatible Type | yes | https://cwe.mitre.org/data/definitions/843.html |
| cwe_85 | Doubled Character XSS Manipulations | yes | https://cwe.mitre.org/data/definitions/85.html |
| cwe_86 | Improper Neutralization of Invalid Characters in Identifiers in Web Pages | yes | https://cwe.mitre.org/data/definitions/86.html |
| cwe_863 | Incorrect Authorization | yes | https://cwe.mitre.org/data/definitions/863.html |
| cwe_87 | Improper Neutralization of Alternate XSS Syntax | yes | https://cwe.mitre.org/data/definitions/87.html |
| cwe_88 | Improper Neutralization of Argument Delimiters in a Command | yes | https://cwe.mitre.org/data/definitions/88.html |
| cwe_9 | J2EE Misconfiguration: Weak Access Permissions for EJB Methods | yes | https://cwe.mitre.org/data/definitions/9.html |
| cwe_90 | Improper Neutralization of Special Elements used in an LDAP Query | yes | https://cwe.mitre.org/data/definitions/90.html |
| cwe_908 | Use of Uninitialized Resource | yes | https://cwe.mitre.org/data/definitions/908.html |
| cwe_909 | Missing Initialization of Resource | yes | https://cwe.mitre.org/data/definitions/909.html |
| cwe_91 | XML Injection | yes | https://cwe.mitre.org/data/definitions/91.html |
| cwe_910 | Use of Expired File Descriptor | yes | https://cwe.mitre.org/data/definitions/910.html |
| cwe_911 | Improper Update of Reference Count | yes | https://cwe.mitre.org/data/definitions/911.html |
| cwe_912 | Hidden Functionality | yes | https://cwe.mitre.org/data/definitions/912.html |
| cwe_913 | Improper Control of Dynamically-Managed Code Resources | yes | https://cwe.mitre.org/data/definitions/913.html |
| cwe_914 | Improper Control of Dynamically-Identified Variables | yes | https://cwe.mitre.org/data/definitions/914.html |
| cwe_916 | Use of Password Hash With Insufficient Computational Effort | yes | https://cwe.mitre.org/data/definitions/916.html |
| cwe_917 | Improper Neutralization of Special Elements used in an Expression Language Statement | yes | https://cwe.mitre.org/data/definitions/917.html |
| cwe_92 | DEPRECATED: Improper Sanitization of Custom Special Characters | no | https://cwe.mitre.org/data/definitions/92.html |
| cwe_920 | Improper Restriction of Power Consumption | yes | https://cwe.mitre.org/data/definitions/920.html |
| cwe_921 | Storage of Sensitive Data in a Mechanism without Access Control | yes | https://cwe.mitre.org/data/definitions/921.html |
| cwe_922 | Insecure Storage of Sensitive Information | yes | https://cwe.mitre.org/data/definitions/922.html |
| cwe_923 | Improper Restriction of Communication Channel to Intended Endpoints | yes | https://cwe.mitre.org/data/definitions/923.html |
| cwe_924 | Improper Enforcement of Message Integrity During Transmission in a Communication Channel | yes | https://cwe.mitre.org/data/definitions/924.html |
| cwe_925 | Improper Verification of Intent by Broadcast Receiver | yes | https://cwe.mitre.org/data/definitions/925.html |
| cwe_926 | Improper Export of Android Application Components | yes | https://cwe.mitre.org/data/definitions/926.html |
| cwe_927 | Use of Implicit Intent for Sensitive Communication | yes | https://cwe.mitre.org/data/definitions/927.html |
| cwe_93 | Improper Neutralization of CRLF Sequences | yes | https://cwe.mitre.org/data/definitions/93.html |
| cwe_939 | Improper Authorization in Handler for Custom URL Scheme | yes | https://cwe.mitre.org/data/definitions/939.html |
| cwe_940 | Improper Verification of Source of a Communication Channel | yes | https://cwe.mitre.org/data/definitions/940.html |
| cwe_941 | Incorrectly Specified Destination in a Communication Channel | yes | https://cwe.mitre.org/data/definitions/941.html |
| cwe_943 | Improper Neutralization of Special Elements in Data Query Logic | yes | https://cwe.mitre.org/data/definitions/943.html |
| cwe_95 | Improper Neutralization of Directives in Dynamically Evaluated Code | yes | https://cwe.mitre.org/data/definitions/95.html |
| cwe_96 | Improper Neutralization of Directives in Statically Saved Code | yes | https://cwe.mitre.org/data/definitions/96.html |
| cwe_97 | Improper Neutralization of Server-Side Includes (SSI) Within a Web Page | yes | https://cwe.mitre.org/data/definitions/97.html |
| cwe_98 | Improper Control of Filename for Include/Require Statement in PHP Program | yes | https://cwe.mitre.org/data/definitions/98.html |
| cwe_99 | Improper Control of Resource Identifiers | yes | https://cwe.mitre.org/data/definitions/99.html |
| dangling_dns_record | Dangling DNS or deprovisioned service reference | yes | https://api-security.owasp.org/editions/2023/en/0xa9-improper-inventory-management/ |
| data_authenticity_failure | Insufficient Verification of Data Authenticity | yes | https://cwe.mitre.org/data/definitions/345.html |
| excessive_agency | Excessive agency | yes | Editorial definition; see v1 provenance |
| hardcoded_credentials | Use of Hard-coded Credentials | yes | https://cwe.mitre.org/data/definitions/798.html |
| http_request_smuggling | Inconsistent Interpretation of HTTP Requests | yes | https://cwe.mitre.org/data/definitions/444.html |
| http_response_splitting | Improper Neutralization of CRLF Sequences in HTTP Headers | yes | https://cwe.mitre.org/data/definitions/113.html |
| idor | Insecure direct object reference | yes | https://cwe.mitre.org/data/definitions/639.html |
| improper_certificate_validation | Improper Certificate Validation | yes | https://cwe.mitre.org/data/definitions/295.html |
| improper_privilege_management | Improper Privilege Management | yes | https://cwe.mitre.org/data/definitions/269.html |
| improper_signature_verification | Improper Verification of Cryptographic Signature | yes | https://cwe.mitre.org/data/definitions/347.html |
| incorrect_permissions | Incorrect Permission Assignment for Critical Resource | yes | https://cwe.mitre.org/data/definitions/732.html |
| indirect_prompt_injection | Indirect prompt injection | yes | Editorial definition; see v1 provenance |
| injection | Injection | no | https://cwe.mitre.org/data/definitions/74.html |
| insecure_cookie_transport | Sensitive Cookie in HTTPS Session Without 'Secure' Attribute | yes | https://cwe.mitre.org/data/definitions/614.html |
| insecure_deserialization | Insecure deserialization | yes | https://cwe.mitre.org/data/definitions/502.html |
| insufficient_session_expiration | DEPRECATED: Insufficient Session Expiration | no | https://cwe.mitre.org/data/definitions/613.html |
| integer_overflow | Integer Overflow or Wraparound | yes | https://cwe.mitre.org/data/definitions/190.html |
| log_injection | Improper Output Neutralization for Logs | yes | https://cwe.mitre.org/data/definitions/117.html |
| mass_assignment | Improperly Controlled Modification of Dynamically-Determined Object Attributes | yes | https://cwe.mitre.org/data/definitions/915.html |
| missing_authentication | Missing Authentication for Critical Functionality | yes | https://cwe.mitre.org/data/definitions/306.html |
| missing_authorization | Missing authorization | yes | https://cwe.mitre.org/data/definitions/862.html |
| missing_httponly_cookie | Sensitive Cookie Without 'HttpOnly' Flag | yes | https://cwe.mitre.org/data/definitions/1004.html |
| missing_rate_limiting | Improper Control of Interaction Frequency | yes | https://cwe.mitre.org/data/definitions/799.html |
| missing_sensitive_data_encryption | Missing Encryption of Sensitive Data | yes | https://cwe.mitre.org/data/definitions/311.html |
| model_or_data_poisoning | Model or training data poisoning | yes | https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/9253e38ade58e959b531c0c5c9a4842272c9cd0e/2026/final/LLM05_DataModelPoisoning.md |
| open_redirect | URL Redirection to Untrusted Site | yes | https://cwe.mitre.org/data/definitions/601.html |
| origin_validation_failure | Origin Validation Error | yes | https://cwe.mitre.org/data/definitions/346.html |
| out_of_bounds_read | Out-of-bounds Read | yes | https://cwe.mitre.org/data/definitions/125.html |
| out_of_bounds_write | Out-of-bounds Write | yes | https://cwe.mitre.org/data/definitions/787.html |
| path_traversal | Path traversal | yes | https://cwe.mitre.org/data/definitions/22.html |
| permissive_cors | Permissive Cross-domain Security Policy with Untrusted Domains | yes | https://cwe.mitre.org/data/definitions/942.html |
| prompt_injection | Prompt injection | yes | https://cwe.mitre.org/data/definitions/1427.html |
| race_condition | Concurrent Execution using Shared Resource with Improper Synchronization | yes | https://cwe.mitre.org/data/definitions/362.html |
| regular_expression_denial_of_service | Inefficient Regular Expression Complexity | yes | https://cwe.mitre.org/data/definitions/1333.html |
| resource_exhaustion | Uncontrolled Resource Consumption | yes | https://cwe.mitre.org/data/definitions/400.html |
| retrieval_or_memory_poisoning | Retrieval, vector or agent memory poisoning | yes | https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/9253e38ade58e959b531c0c5c9a4842272c9cd0e/2026/final/LLM09_VectorAndEmbeddingWeaknesses.md |
| security_misconfiguration | Security misconfiguration | yes | https://top10.owasp.org/2025/A02_2025-Security_Misconfiguration/ |
| sensitive_data_exposure | Sensitive data exposure | yes | https://cwe.mitre.org/data/definitions/200.html |
| sensitive_data_in_logs | Insertion of Sensitive Information into Log File | yes | https://cwe.mitre.org/data/definitions/532.html |
| session_fixation | Session Fixation | yes | https://cwe.mitre.org/data/definitions/384.html |
| sql_injection | SQL injection | yes | https://cwe.mitre.org/data/definitions/89.html |
| ssrf | Server-side request forgery | yes | https://cwe.mitre.org/data/definitions/918.html |
| stored_xss | Stored cross-site scripting | yes | Editorial definition; see v1 provenance |
| subdomain_takeover | Subdomain takeover | yes | https://api-security.owasp.org/editions/2023/en/0xa9-improper-inventory-management/ |
| system_prompt_exposure | Hidden instruction or system prompt exposure | yes | https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/9253e38ade58e959b531c0c5c9a4842272c9cd0e/2026/final/LLM08_HiddenContextExposure.md |
| template_injection | Improper Neutralization of Special Elements Used in a Template Engine | yes | https://cwe.mitre.org/data/definitions/1336.html |
| timing_side_channel | Observable Timing Discrepancy | yes | https://cwe.mitre.org/data/definitions/208.html |
| unbounded_resource_consumption | Allocation of Resources Without Limits or Throttling | yes | https://cwe.mitre.org/data/definitions/770.html |
| unmaintained_dependency | Use of Unmaintained Third Party Components | yes | https://cwe.mitre.org/data/definitions/1104.html |
| unrestricted_file_upload | Unrestricted Upload of File with Dangerous Type | yes | https://cwe.mitre.org/data/definitions/434.html |
| unsafe_model_output_handling | Improper Validation of Generative AI Output | yes | https://cwe.mitre.org/data/definitions/1426.html |
| unsafe_model_reliance | Unsafe reliance on model output | yes | https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/9253e38ade58e959b531c0c5c9a4842272c9cd0e/2026/final/LLM07_Misinformation.md |
| unsafe_tool_use | Unsafe tool use | yes | Editorial definition; see v1 provenance |
| use_after_free | Use After Free | yes | https://cwe.mitre.org/data/definitions/416.html |
| verbose_error_disclosure | Generation of Error Message Containing Sensitive Information | yes | https://cwe.mitre.org/data/definitions/209.html |
| vulnerable_dependency | Dependency on Vulnerable Third-Party Component | yes | https://cwe.mitre.org/data/definitions/1395.html |
| weak_cryptography | Use of a Broken or Risky Cryptographic Algorithm | yes | https://cwe.mitre.org/data/definitions/327.html |
| xml_external_entity | Improper Restriction of XML External Entity Reference | yes | https://cwe.mitre.org/data/definitions/611.html |

## AIUC-1

| ID | Name | Kind |
| --- | --- | --- |
| aiuc-1:A001 | Input usage rules | requirement_reference |
| aiuc-1:A002 | Output usage rules | requirement_reference |
| aiuc-1:A003 | Data access boundaries | requirement_reference |
| aiuc-1:A004 | Confidential intellectual assets | requirement_reference |
| aiuc-1:A005 | Customer data isolation | requirement_reference |
| aiuc-1:A006 | Personal data safeguards | requirement_reference |
| aiuc-1:A007 | Intellectual property safeguards | requirement_reference |
| aiuc-1:A008 | Credential confidentiality | requirement_reference |
| aiuc-1:A009 | Independent privacy testing | requirement_reference |
| aiuc-1:B001 | Independent security evaluation | requirement_reference |
| aiuc-1:B002 | Adversarial input recognition | requirement_reference |
| aiuc-1:B003 | Controlled technical disclosure | requirement_reference |
| aiuc-1:B004 | Endpoint extraction resistance | requirement_reference |
| aiuc-1:B005 | Live input inspection | requirement_reference |
| aiuc-1:B006 | Agent action authorization | requirement_reference |
| aiuc-1:B007 | User privilege enforcement | requirement_reference |
| aiuc-1:B008 | Deployment infrastructure protection | requirement_reference |
| aiuc-1:B009 | Output disclosure boundaries | requirement_reference |
| aiuc-1:B010 | Secure code generation | requirement_reference |
| aiuc-1:C001 | Risk classification model | requirement_reference |
| aiuc-1:C002 | Release readiness testing | requirement_reference |
| aiuc-1:C003 | Harm prevention | requirement_reference |
| aiuc-1:C004 | Output scope boundaries | requirement_reference |
| aiuc-1:C005 | Agent hazard safeguards | requirement_reference |
| aiuc-1:C006 | Output security safeguards | requirement_reference |
| aiuc-1:C007 | Human escalation | requirement_reference |
| aiuc-1:C008 | Continuous risk observation | requirement_reference |
| aiuc-1:C009 | Feedback and intervention | requirement_reference |
| aiuc-1:C010 | Independent safety testing | requirement_reference |
| aiuc-1:D001 | Factual output reliability | requirement_reference |
| aiuc-1:D003 | Tool invocation boundaries | requirement_reference |
| aiuc-1:D004 | Independent reliability testing | requirement_reference |
| aiuc-1:E001 | Security incident preparation | requirement_reference |
| aiuc-1:E002 | Harm incident preparation | requirement_reference |
| aiuc-1:E003 | Factual failure preparation | requirement_reference |
| aiuc-1:E004 | Accountable ownership | requirement_reference |
| aiuc-1:E005 | Storage security documentation | requirement_reference |
| aiuc-1:E006 | Supplier due diligence | requirement_reference |
| aiuc-1:E008 | Process assurance reviews | requirement_reference |
| aiuc-1:E009 | Supplier access oversight | requirement_reference |
| aiuc-1:E010 | Acceptable use rules | requirement_reference |
| aiuc-1:E011 | Processing geography records | requirement_reference |
| aiuc-1:E012 | Regulatory obligations register | requirement_reference |
| aiuc-1:E013 | Quality assurance system | requirement_reference |
| aiuc-1:E015 | Agent activity records | requirement_reference |
| aiuc-1:E016 | AI interaction disclosure | requirement_reference |
| aiuc-1:E017 | Transparency commitments | requirement_reference |
| aiuc-1:E018 | Independent accountability testing | requirement_reference |
| aiuc-1:F001 | Cyber misuse safeguards | requirement_reference |
| aiuc-1:F002 | Catastrophic misuse safeguards | requirement_reference |

## MITRE CWE

| ID | Name | Kind |
| --- | --- | --- |
| cwe:CWE-1004 | Sensitive Cookie Without 'HttpOnly' Flag | weakness |
| cwe:CWE-1007 | Insufficient Visual Distinction of Homoglyphs Presented to User | weakness |
| cwe:CWE-102 | Struts: Duplicate Validation Forms | weakness |
| cwe:CWE-1021 | Improper Restriction of Rendered UI Layers or Frames | weakness |
| cwe:CWE-1022 | Use of Web Link to Untrusted Target with window.opener Access | weakness |
| cwe:CWE-1023 | Incomplete Comparison with Missing Factors | weakness |
| cwe:CWE-1024 | Comparison of Incompatible Types | weakness |
| cwe:CWE-1025 | Comparison Using Wrong Factors | weakness |
| cwe:CWE-103 | Struts: Incomplete validate() Method Definition | weakness |
| cwe:CWE-1037 | Processor Optimization Removal or Modification of Security-critical Code | weakness |
| cwe:CWE-1038 | Insecure Automated Optimizations | weakness |
| cwe:CWE-1039 | Inadequate Detection or Handling of Adversarial Input Perturbations in Automated Recognition Mechanism | weakness |
| cwe:CWE-104 | Struts: Form Bean Does Not Extend Validation Class | weakness |
| cwe:CWE-1041 | Use of Redundant Code | weakness |
| cwe:CWE-1042 | Static Member Data Element outside of a Singleton Class Element | weakness |
| cwe:CWE-1043 | Data Element Aggregating an Excessively Large Number of Non-Primitive Elements | weakness |
| cwe:CWE-1044 | Architecture with Number of Horizontal Layers Outside of Expected Range | weakness |
| cwe:CWE-1045 | Parent Class with a Virtual Destructor and a Child Class without a Virtual Destructor | weakness |
| cwe:CWE-1046 | Creation of Immutable Text Using String Concatenation | weakness |
| cwe:CWE-1047 | Modules with Circular Dependencies | weakness |
| cwe:CWE-1048 | Invokable Control Element with Large Number of Outward Calls | weakness |
| cwe:CWE-1049 | Excessive Data Query Operations in a Large Data Table | weakness |
| cwe:CWE-105 | Struts: Form Field Without Validator | weakness |
| cwe:CWE-1050 | Excessive Platform Resource Consumption within a Loop | weakness |
| cwe:CWE-1051 | Initialization with Hard-Coded Network Resource Configuration Data | weakness |
| cwe:CWE-1052 | Excessive Use of Hard-Coded Literals in Initialization | weakness |
| cwe:CWE-1053 | Missing Documentation for Design | weakness |
| cwe:CWE-1054 | Invocation of a Control Element at an Unnecessarily Deep Horizontal Layer | weakness |
| cwe:CWE-1055 | Multiple Inheritance from Concrete Classes | weakness |
| cwe:CWE-1056 | Invokable Control Element with Variadic Parameters | weakness |
| cwe:CWE-1057 | Data Access Operations Outside of Expected Data Manager Component | weakness |
| cwe:CWE-1058 | Invokable Control Element in Multi-Thread Context with non-Final Static Storable or Member Element | weakness |
| cwe:CWE-1059 | Insufficient Technical Documentation | weakness |
| cwe:CWE-106 | Struts: Plug-in Framework not in Use | weakness |
| cwe:CWE-1060 | Excessive Number of Inefficient Server-Side Data Accesses | weakness |
| cwe:CWE-1061 | Insufficient Encapsulation | weakness |
| cwe:CWE-1062 | Parent Class with References to Child Class | weakness |
| cwe:CWE-1063 | Creation of Class Instance within a Static Code Block | weakness |
| cwe:CWE-1064 | Invokable Control Element with Signature Containing an Excessive Number of Parameters | weakness |
| cwe:CWE-1065 | Runtime Resource Management Control Element in a Component Built to Run on Application Servers | weakness |
| cwe:CWE-1066 | Missing Serialization Control Element | weakness |
| cwe:CWE-1067 | Excessive Execution of Sequential Searches of Data Resource | weakness |
| cwe:CWE-1068 | Inconsistency Between Implementation and Documented Design | weakness |
| cwe:CWE-1069 | Empty Exception Block | weakness |
| cwe:CWE-107 | Struts: Unused Validation Form | weakness |
| cwe:CWE-1070 | Serializable Data Element Containing non-Serializable Item Elements | weakness |
| cwe:CWE-1071 | Empty Code Block | weakness |
| cwe:CWE-1072 | Data Resource Access without Use of Connection Pooling | weakness |
| cwe:CWE-1073 | Non-SQL Invokable Control Element with Excessive Number of Data Resource Accesses | weakness |
| cwe:CWE-1074 | Class with Excessively Deep Inheritance | weakness |
| cwe:CWE-1075 | Unconditional Control Flow Transfer outside of Switch Block | weakness |
| cwe:CWE-1076 | Insufficient Adherence to Expected Conventions | weakness |
| cwe:CWE-1077 | Floating Point Comparison with Incorrect Operator | weakness |
| cwe:CWE-1078 | Inappropriate Source Code Style or Formatting | weakness |
| cwe:CWE-1079 | Parent Class without Virtual Destructor Method | weakness |
| cwe:CWE-108 | Struts: Unvalidated Action Form | weakness |
| cwe:CWE-1080 | Source Code File with Excessive Number of Lines of Code | weakness |
| cwe:CWE-1082 | Class Instance Self Destruction Control Element | weakness |
| cwe:CWE-1083 | Data Access from Outside Expected Data Manager Component | weakness |
| cwe:CWE-1084 | Invokable Control Element with Excessive File or Data Access Operations | weakness |
| cwe:CWE-1085 | Invokable Control Element with Excessive Volume of Commented-out Code | weakness |
| cwe:CWE-1086 | Class with Excessive Number of Child Classes | weakness |
| cwe:CWE-1087 | Class with Virtual Method without a Virtual Destructor | weakness |
| cwe:CWE-1088 | Synchronous Access of Remote Resource without Timeout | weakness |
| cwe:CWE-1089 | Large Data Table with Excessive Number of Indices | weakness |
| cwe:CWE-109 | Struts: Validator Turned Off | weakness |
| cwe:CWE-1090 | Method Containing Access of a Member Element from Another Class | weakness |
| cwe:CWE-1091 | Use of Object without Invoking Destructor Method | weakness |
| cwe:CWE-1092 | Use of Same Invokable Control Element in Multiple Architectural Layers | weakness |
| cwe:CWE-1093 | Excessively Complex Data Representation | weakness |
| cwe:CWE-1094 | Excessive Index Range Scan for a Data Resource | weakness |
| cwe:CWE-1095 | Loop Condition Value Update within the Loop | weakness |
| cwe:CWE-1096 | Singleton Class Instance Creation without Proper Locking or Synchronization | weakness |
| cwe:CWE-1097 | Persistent Storable Data Element without Associated Comparison Control Element | weakness |
| cwe:CWE-1098 | Data Element containing Pointer Item without Proper Copy Control Element | weakness |
| cwe:CWE-1099 | Inconsistent Naming Conventions for Identifiers | weakness |
| cwe:CWE-11 | ASP.NET Misconfiguration: Creating Debug Binary | weakness |
| cwe:CWE-110 | Struts: Validator Without Form Field | weakness |
| cwe:CWE-1100 | Insufficient Isolation of System-Dependent Functions | weakness |
| cwe:CWE-1101 | Reliance on Runtime Component in Generated Code | weakness |
| cwe:CWE-1102 | Reliance on Machine-Dependent Data Representation | weakness |
| cwe:CWE-1103 | Use of Platform-Dependent Third Party Components | weakness |
| cwe:CWE-1104 | Use of Unmaintained Third Party Components | weakness |
| cwe:CWE-1105 | Insufficient Encapsulation of Machine-Dependent Functionality | weakness |
| cwe:CWE-1106 | Insufficient Use of Symbolic Constants | weakness |
| cwe:CWE-1107 | Insufficient Isolation of Symbolic Constant Definitions | weakness |
| cwe:CWE-1108 | Excessive Reliance on Global Variables | weakness |
| cwe:CWE-1109 | Use of Same Variable for Multiple Purposes | weakness |
| cwe:CWE-111 | Direct Use of Unsafe JNI | weakness |
| cwe:CWE-1110 | Incomplete Design Documentation | weakness |
| cwe:CWE-1111 | Incomplete I/O Documentation | weakness |
| cwe:CWE-1112 | Incomplete Documentation of Program Execution | weakness |
| cwe:CWE-1113 | Inappropriate Comment Style | weakness |
| cwe:CWE-1114 | Inappropriate Whitespace Style | weakness |
| cwe:CWE-1115 | Source Code Element without Standard Prologue | weakness |
| cwe:CWE-1116 | Inaccurate Source Code Comments | weakness |
| cwe:CWE-1117 | Callable with Insufficient Behavioral Summary | weakness |
| cwe:CWE-1118 | Insufficient Documentation of Error Handling Techniques | weakness |
| cwe:CWE-1119 | Excessive Use of Unconditional Branching | weakness |
| cwe:CWE-112 | Missing XML Validation | weakness |
| cwe:CWE-1120 | Excessive Code Complexity | weakness |
| cwe:CWE-1121 | Excessive McCabe Cyclomatic Complexity | weakness |
| cwe:CWE-1122 | Excessive Halstead Complexity | weakness |
| cwe:CWE-1123 | Excessive Use of Self-Modifying Code | weakness |
| cwe:CWE-1124 | Excessively Deep Nesting | weakness |
| cwe:CWE-1125 | Excessive Attack Surface | weakness |
| cwe:CWE-1126 | Declaration of Variable with Unnecessarily Wide Scope | weakness |
| cwe:CWE-1127 | Compilation with Insufficient Warnings or Errors | weakness |
| cwe:CWE-113 | Improper Neutralization of CRLF Sequences in HTTP Headers | weakness |
| cwe:CWE-114 | Process Control | weakness |
| cwe:CWE-115 | Misinterpretation of Input | weakness |
| cwe:CWE-116 | Improper Encoding or Escaping of Output | weakness |
| cwe:CWE-1164 | Irrelevant Code | weakness |
| cwe:CWE-117 | Improper Output Neutralization for Logs | weakness |
| cwe:CWE-1173 | Improper Use of Validation Framework | weakness |
| cwe:CWE-1174 | ASP.NET Misconfiguration: Improper Model Validation | weakness |
| cwe:CWE-1176 | Inefficient CPU Computation | weakness |
| cwe:CWE-1177 | Use of Prohibited Code | weakness |
| cwe:CWE-118 | Incorrect Access of Indexable Resource | weakness |
| cwe:CWE-1187 | DEPRECATED: Use of Uninitialized Resource | weakness (deprecated) |
| cwe:CWE-1188 | Initialization of a Resource with an Insecure Default | weakness |
| cwe:CWE-1189 | Improper Isolation of Shared Resources on System-on-a-Chip (SoC) | weakness |
| cwe:CWE-119 | Improper Restriction of Operations within the Bounds of a Memory Buffer | weakness |
| cwe:CWE-1190 | DMA Device Enabled Too Early in Boot Phase | weakness |
| cwe:CWE-1191 | On-Chip Debug and Test Interface With Improper Access Control | weakness |
| cwe:CWE-1192 | Improper Identifier for IP Block used in System-On-Chip (SOC) | weakness |
| cwe:CWE-1193 | Power-On of Untrusted Execution Core Before Enabling Fabric Access Control | weakness |
| cwe:CWE-12 | ASP.NET Misconfiguration: Missing Custom Error Page | weakness |
| cwe:CWE-120 | Buffer Copy without Checking Size of Input | weakness |
| cwe:CWE-1204 | Generation of Weak Initialization Vector (IV) | weakness |
| cwe:CWE-1209 | Failure to Disable Reserved Bits | weakness |
| cwe:CWE-121 | Stack-based Buffer Overflow | weakness |
| cwe:CWE-122 | Heap-based Buffer Overflow | weakness |
| cwe:CWE-1220 | Insufficient Granularity of Access Control | weakness |
| cwe:CWE-1221 | Incorrect Register Defaults or Module Parameters | weakness |
| cwe:CWE-1222 | Insufficient Granularity of Address Regions Protected by Register Locks | weakness |
| cwe:CWE-1223 | Race Condition for Write-Once Attributes | weakness |
| cwe:CWE-1224 | Improper Restriction of Write-Once Bit Fields | weakness |
| cwe:CWE-1229 | Creation of Emergent Resource | weakness |
| cwe:CWE-123 | Write-what-where Condition | weakness |
| cwe:CWE-1230 | Exposure of Sensitive Information Through Metadata | weakness |
| cwe:CWE-1231 | Improper Prevention of Lock Bit Modification | weakness |
| cwe:CWE-1232 | Improper Lock Behavior After Power State Transition | weakness |
| cwe:CWE-1233 | Security-Sensitive Hardware Controls with Missing Lock Bit Protection | weakness |
| cwe:CWE-1234 | Hardware Internal or Debug Modes Allow Override of Locks | weakness |
| cwe:CWE-1235 | Incorrect Use of Autoboxing and Unboxing for Performance Critical Operations | weakness |
| cwe:CWE-1236 | Improper Neutralization of Formula Elements in a CSV File | weakness |
| cwe:CWE-1239 | Improper Zeroization of Hardware Register | weakness |
| cwe:CWE-124 | Buffer Underwrite | weakness |
| cwe:CWE-1240 | Use of a Cryptographic Primitive with a Risky Implementation | weakness |
| cwe:CWE-1241 | Use of Predictable Algorithm in Random Number Generator | weakness |
| cwe:CWE-1242 | Inclusion of Undocumented Features or Chicken Bits | weakness |
| cwe:CWE-1243 | Sensitive Non-Volatile Information Not Protected During Debug | weakness |
| cwe:CWE-1244 | Internal Asset Exposed to Unsafe Debug Access Level or State | weakness |
| cwe:CWE-1245 | Improper Finite State Machines (FSMs) in Hardware Logic | weakness |
| cwe:CWE-1246 | Improper Write Handling in Limited-write Non-Volatile Memories | weakness |
| cwe:CWE-1247 | Improper Protection Against Voltage and Clock Glitches | weakness |
| cwe:CWE-1248 | Semiconductor Defects in Hardware Logic with Security-Sensitive Implications | weakness |
| cwe:CWE-1249 | Application-Level Admin Tool with Inconsistent View of Underlying Operating System | weakness |
| cwe:CWE-125 | Out-of-bounds Read | weakness |
| cwe:CWE-1250 | Improper Preservation of Consistency Between Independent Representations of Shared State | weakness |
| cwe:CWE-1251 | Mirrored Regions with Different Values | weakness |
| cwe:CWE-1252 | CPU Hardware Not Configured to Support Exclusivity of Write and Execute Operations | weakness |
| cwe:CWE-1253 | Incorrect Selection of Fuse Values | weakness |
| cwe:CWE-1254 | Incorrect Comparison Logic Granularity | weakness |
| cwe:CWE-1255 | Comparison Logic is Vulnerable to Power Side-Channel Attacks | weakness |
| cwe:CWE-1256 | Improper Restriction of Software Interfaces to Hardware Features | weakness |
| cwe:CWE-1257 | Improper Access Control Applied to Mirrored or Aliased Memory Regions | weakness |
| cwe:CWE-1258 | Exposure of Sensitive System Information Due to Uncleared Debug Information | weakness |
| cwe:CWE-1259 | Improper Restriction of Security Token Assignment | weakness |
| cwe:CWE-126 | Buffer Over-read | weakness |
| cwe:CWE-1260 | Improper Handling of Overlap Between Protected Memory Ranges | weakness |
| cwe:CWE-1261 | Improper Handling of Single Event Upsets | weakness |
| cwe:CWE-1262 | Improper Access Control for Register Interface | weakness |
| cwe:CWE-1263 | Improper Physical Access Control | weakness |
| cwe:CWE-1264 | Hardware Logic with Insecure De-Synchronization between Control and Data Channels | weakness |
| cwe:CWE-1265 | Unintended Reentrant Invocation of Non-reentrant Code Via Nested Calls | weakness |
| cwe:CWE-1266 | Improper Scrubbing of Sensitive Data from Decommissioned Device | weakness |
| cwe:CWE-1267 | Policy Uses Obsolete Encoding | weakness |
| cwe:CWE-1268 | Policy Privileges are not Assigned Consistently Between Control and Data Agents | weakness |
| cwe:CWE-1269 | Product Released in Non-Release Configuration | weakness |
| cwe:CWE-127 | Buffer Under-read | weakness |
| cwe:CWE-1270 | Generation of Incorrect Security Tokens | weakness |
| cwe:CWE-1271 | Uninitialized Value on Reset for Registers Holding Security Settings | weakness |
| cwe:CWE-1272 | Sensitive Information Uncleared Before Debug/Power State Transition | weakness |
| cwe:CWE-1273 | Device Unlock Credential Sharing | weakness |
| cwe:CWE-1274 | Improper Access Control for Volatile Memory Containing Boot Code | weakness |
| cwe:CWE-1275 | Sensitive Cookie with Improper SameSite Attribute | weakness |
| cwe:CWE-1276 | Hardware Child Block Incorrectly Connected to Parent System | weakness |
| cwe:CWE-1277 | Firmware Not Updateable | weakness |
| cwe:CWE-1278 | Missing Protection Against Hardware Reverse Engineering Using Integrated Circuit (IC) Imaging Techniques | weakness |
| cwe:CWE-1279 | Cryptographic Operations are Run Before Supporting Units are Ready | weakness |
| cwe:CWE-128 | Wrap-around Error | weakness |
| cwe:CWE-1280 | Access Control Check Implemented After Asset is Accessed | weakness |
| cwe:CWE-1281 | Sequence of Processor Instructions Leads to Unexpected Behavior | weakness |
| cwe:CWE-1282 | Assumed-Immutable Data is Stored in Writable Memory | weakness |
| cwe:CWE-1283 | Mutable Attestation or Measurement Reporting Data | weakness |
| cwe:CWE-1284 | Improper Validation of Specified Quantity in Input | weakness |
| cwe:CWE-1285 | Improper Validation of Specified Index, Position, or Offset in Input | weakness |
| cwe:CWE-1286 | Improper Validation of Syntactic Correctness of Input | weakness |
| cwe:CWE-1287 | Improper Validation of Specified Type of Input | weakness |
| cwe:CWE-1288 | Improper Validation of Consistency within Input | weakness |
| cwe:CWE-1289 | Improper Validation of Unsafe Equivalence in Input | weakness |
| cwe:CWE-129 | Improper Validation of Array Index | weakness |
| cwe:CWE-1290 | Incorrect Decoding of Security Identifiers | weakness |
| cwe:CWE-1291 | Public Key Re-Use for Signing both Debug and Production Code | weakness |
| cwe:CWE-1292 | Incorrect Conversion of Security Identifiers | weakness |
| cwe:CWE-1293 | Missing Source Correlation of Multiple Independent Data | weakness |
| cwe:CWE-1294 | Insecure Security Identifier Mechanism | weakness |
| cwe:CWE-1295 | Debug Messages Revealing Unnecessary Information | weakness |
| cwe:CWE-1296 | Incorrect Chaining or Granularity of Debug Components | weakness |
| cwe:CWE-1297 | Unprotected Confidential Information on Device is Accessible by OSAT Vendors | weakness |
| cwe:CWE-1298 | Hardware Logic Contains Race Conditions | weakness |
| cwe:CWE-1299 | Missing Protection Mechanism for Alternate Hardware Interface | weakness |
| cwe:CWE-13 | ASP.NET Misconfiguration: Password in Configuration File | weakness |
| cwe:CWE-130 | Improper Handling of Length Parameter Inconsistency | weakness |
| cwe:CWE-1300 | Improper Protection of Physical Side Channels | weakness |
| cwe:CWE-1301 | Insufficient or Incomplete Data Removal within Hardware Component | weakness |
| cwe:CWE-1302 | Missing Source Identifier in Entity Transactions on a System-On-Chip (SOC) | weakness |
| cwe:CWE-1303 | Non-Transparent Sharing of Microarchitectural Resources | weakness |
| cwe:CWE-1304 | Improperly Preserved Integrity of Hardware Configuration State During a Power Save/Restore Operation | weakness |
| cwe:CWE-131 | Incorrect Calculation of Buffer Size | weakness |
| cwe:CWE-1310 | Missing Ability to Patch ROM Code | weakness |
| cwe:CWE-1311 | Improper Translation of Security Attributes by Fabric Bridge | weakness |
| cwe:CWE-1312 | Missing Protection for Mirrored Regions in On-Chip Fabric Firewall | weakness |
| cwe:CWE-1313 | Hardware Allows Activation of Test or Debug Logic at Runtime | weakness |
| cwe:CWE-1314 | Missing Write Protection for Parametric Data Values | weakness |
| cwe:CWE-1315 | Improper Setting of Bus Controlling Capability in Fabric End-point | weakness |
| cwe:CWE-1316 | Fabric-Address Map Allows Programming of Unwarranted Overlaps of Protected and Unprotected Ranges | weakness |
| cwe:CWE-1317 | Improper Access Control in Fabric Bridge | weakness |
| cwe:CWE-1318 | Missing Support for Security Features in On-chip Fabrics or Buses | weakness |
| cwe:CWE-1319 | Improper Protection against Electromagnetic Fault Injection (EM-FI) | weakness |
| cwe:CWE-132 | DEPRECATED: Miscalculated Null Termination | weakness (deprecated) |
| cwe:CWE-1320 | Improper Protection for Outbound Error Messages and Alert Signals | weakness |
| cwe:CWE-1321 | Improperly Controlled Modification of Object Prototype Attributes | weakness |
| cwe:CWE-1322 | Use of Blocking Code in Single-threaded, Non-blocking Context | weakness |
| cwe:CWE-1323 | Improper Management of Sensitive Trace Data | weakness |
| cwe:CWE-1324 | DEPRECATED: Sensitive Information Accessible by Physical Probing of JTAG Interface | weakness (deprecated) |
| cwe:CWE-1325 | Improperly Controlled Sequential Memory Allocation | weakness |
| cwe:CWE-1326 | Missing Immutable Root of Trust in Hardware | weakness |
| cwe:CWE-1327 | Binding to an Unrestricted IP Address | weakness |
| cwe:CWE-1328 | Security Version Number Mutable to Older Versions | weakness |
| cwe:CWE-1329 | Reliance on Component That is Not Updateable | weakness |
| cwe:CWE-1330 | Remanent Data Readable after Memory Erase | weakness |
| cwe:CWE-1331 | Improper Isolation of Shared Resources in Network On Chip (NoC) | weakness |
| cwe:CWE-1332 | Improper Handling of Faults that Lead to Instruction Skips | weakness |
| cwe:CWE-1333 | Inefficient Regular Expression Complexity | weakness |
| cwe:CWE-1334 | Unauthorized Error Injection Can Degrade Hardware Redundancy | weakness |
| cwe:CWE-1335 | Incorrect Bitwise Shift of Integer | weakness |
| cwe:CWE-1336 | Improper Neutralization of Special Elements Used in a Template Engine | weakness |
| cwe:CWE-1338 | Improper Protections Against Hardware Overheating | weakness |
| cwe:CWE-1339 | Insufficient Precision or Accuracy of a Real Number | weakness |
| cwe:CWE-134 | Use of Externally-Controlled Format String | weakness |
| cwe:CWE-1341 | Multiple Releases of Same Resource or Handle | weakness |
| cwe:CWE-1342 | Information Exposure through Microarchitectural State after Transient Execution | weakness |
| cwe:CWE-135 | Incorrect Calculation of Multi-Byte String Length | weakness |
| cwe:CWE-1351 | Improper Handling of Hardware Behavior in Exceptionally Cold Environments | weakness |
| cwe:CWE-1357 | Reliance on Insufficiently Trustworthy Component | weakness |
| cwe:CWE-138 | Improper Neutralization of Special Elements | weakness |
| cwe:CWE-1384 | Improper Handling of Physical or Environmental Conditions | weakness |
| cwe:CWE-1385 | Missing Origin Validation in WebSockets | weakness |
| cwe:CWE-1386 | Insecure Operation on Windows Junction / Mount Point | weakness |
| cwe:CWE-1389 | Incorrect Parsing of Numbers with Different Radices | weakness |
| cwe:CWE-1390 | Weak Authentication | weakness |
| cwe:CWE-1391 | Use of Weak Credentials | weakness |
| cwe:CWE-1392 | Use of Default Credentials | weakness |
| cwe:CWE-1393 | Use of Default Password | weakness |
| cwe:CWE-1394 | Use of Default Cryptographic Key | weakness |
| cwe:CWE-1395 | Dependency on Vulnerable Third-Party Component | weakness |
| cwe:CWE-14 | Compiler Removal of Code to Clear Buffers | weakness |
| cwe:CWE-140 | Improper Neutralization of Delimiters | weakness |
| cwe:CWE-141 | Improper Neutralization of Parameter/Argument Delimiters | weakness |
| cwe:CWE-1419 | Incorrect Initialization of Resource | weakness |
| cwe:CWE-142 | Improper Neutralization of Value Delimiters | weakness |
| cwe:CWE-1420 | Exposure of Sensitive Information during Transient Execution | weakness |
| cwe:CWE-1421 | Exposure of Sensitive Information in Shared Microarchitectural Structures during Transient Execution | weakness |
| cwe:CWE-1422 | Exposure of Sensitive Information caused by Incorrect Data Forwarding during Transient Execution | weakness |
| cwe:CWE-1423 | Exposure of Sensitive Information caused by Shared Microarchitectural Predictor State that Influences Transient Execution | weakness |
| cwe:CWE-1426 | Improper Validation of Generative AI Output | weakness |
| cwe:CWE-1427 | Improper Neutralization of Input Used for LLM Prompting | weakness |
| cwe:CWE-1428 | Reliance on HTTP instead of HTTPS | weakness |
| cwe:CWE-1429 | Missing Security-Relevant Feedback for Unexecuted Operations in Hardware Interface | weakness |
| cwe:CWE-143 | Improper Neutralization of Record Delimiters | weakness |
| cwe:CWE-1431 | Driving Intermediate Cryptographic State/Results to Hardware Module Outputs | weakness |
| cwe:CWE-1434 | Insecure Setting of Generative AI/ML Model Inference Parameters | weakness |
| cwe:CWE-144 | Improper Neutralization of Line Delimiters | weakness |
| cwe:CWE-145 | Improper Neutralization of Section Delimiters | weakness |
| cwe:CWE-146 | Improper Neutralization of Expression/Command Delimiters | weakness |
| cwe:CWE-1461 | Hardware Simulation / Synthesis Mismatch | weakness |
| cwe:CWE-1462 | Improper Session Management | weakness |
| cwe:CWE-1463 | Insufficient Session Timeout Value | weakness |
| cwe:CWE-1464 | Improper Session Invalidation | weakness |
| cwe:CWE-1465 | Improper Session Invalidation after User Logout | weakness |
| cwe:CWE-1466 | Improper Session Invalidation after Authentication Credential Change | weakness |
| cwe:CWE-1467 | Use of Singular Authentication Artifact for Multiple User Sessions | weakness |
| cwe:CWE-1469 | Improper Check for Credential Expiration | weakness |
| cwe:CWE-147 | Improper Neutralization of Input Terminators | weakness |
| cwe:CWE-1470 | Improper External Identity Verification | weakness |
| cwe:CWE-1471 | Insufficiently Controlled Parser Differential | weakness |
| cwe:CWE-1472 | Generation of Credential with Long Expiration | weakness |
| cwe:CWE-1473 | Improper Expiration of Cached Data | weakness |
| cwe:CWE-1474 | Non-Equivalent Data Transformation | weakness |
| cwe:CWE-1475 | Incomplete Data/State Propagation | weakness |
| cwe:CWE-1476 | Improper Request Propagation before Data Reception in Write Transactions in a Bus Architecture | weakness |
| cwe:CWE-148 | Improper Neutralization of Input Leaders | weakness |
| cwe:CWE-149 | Improper Neutralization of Quoting Syntax | weakness |
| cwe:CWE-15 | External Control of System or Configuration Setting | weakness |
| cwe:CWE-150 | Improper Neutralization of Escape, Meta, or Control Sequences | weakness |
| cwe:CWE-151 | Improper Neutralization of Comment Delimiters | weakness |
| cwe:CWE-152 | Improper Neutralization of Macro Symbols | weakness |
| cwe:CWE-153 | Improper Neutralization of Substitution Characters | weakness |
| cwe:CWE-154 | Improper Neutralization of Variable Name Delimiters | weakness |
| cwe:CWE-155 | Improper Neutralization of Wildcards or Matching Symbols | weakness |
| cwe:CWE-156 | Improper Neutralization of Whitespace | weakness |
| cwe:CWE-157 | Failure to Sanitize Paired Delimiters | weakness |
| cwe:CWE-158 | Improper Neutralization of Null Byte or NUL Character | weakness |
| cwe:CWE-159 | Improper Handling of Invalid Use of Special Elements | weakness |
| cwe:CWE-160 | Improper Neutralization of Leading Special Elements | weakness |
| cwe:CWE-161 | Improper Neutralization of Multiple Leading Special Elements | weakness |
| cwe:CWE-162 | Improper Neutralization of Trailing Special Elements | weakness |
| cwe:CWE-163 | Improper Neutralization of Multiple Trailing Special Elements | weakness |
| cwe:CWE-164 | Improper Neutralization of Internal Special Elements | weakness |
| cwe:CWE-165 | Improper Neutralization of Multiple Internal Special Elements | weakness |
| cwe:CWE-166 | Improper Handling of Missing Special Element | weakness |
| cwe:CWE-167 | Improper Handling of Additional Special Element | weakness |
| cwe:CWE-168 | Improper Handling of Inconsistent Special Elements | weakness |
| cwe:CWE-170 | Improper Null Termination | weakness |
| cwe:CWE-172 | Improper Encoding or Decoding of Data | weakness |
| cwe:CWE-173 | Improper Handling of Alternate Encoding | weakness |
| cwe:CWE-174 | Double Decoding of the Same Data | weakness |
| cwe:CWE-175 | Improper Handling of Mixed Encoding | weakness |
| cwe:CWE-176 | Improper Handling of Unicode Encoding | weakness |
| cwe:CWE-177 | Improper Handling of URL Encoding (Hex Encoding) | weakness |
| cwe:CWE-178 | Improper Handling of Case Sensitivity | weakness |
| cwe:CWE-179 | Incorrect Behavior Order: Early Validation | weakness |
| cwe:CWE-180 | Incorrect Behavior Order: Validate Before Canonicalize | weakness |
| cwe:CWE-181 | Incorrect Behavior Order: Validate Before Filter | weakness |
| cwe:CWE-182 | Collapse of Data into Unsafe Value | weakness |
| cwe:CWE-183 | Permissive List of Allowed Inputs | weakness |
| cwe:CWE-184 | Incomplete List of Disallowed Inputs | weakness |
| cwe:CWE-185 | Incorrect Regular Expression | weakness |
| cwe:CWE-186 | Overly Restrictive Regular Expression | weakness |
| cwe:CWE-187 | Partial String Comparison | weakness |
| cwe:CWE-188 | Reliance on Data/Memory Layout | weakness |
| cwe:CWE-190 | Integer Overflow or Wraparound | weakness |
| cwe:CWE-191 | Integer Underflow (Wrap or Wraparound) | weakness |
| cwe:CWE-192 | Integer Coercion Error | weakness |
| cwe:CWE-193 | Off-by-one Error | weakness |
| cwe:CWE-194 | Unexpected Sign Extension | weakness |
| cwe:CWE-195 | Signed to Unsigned Conversion Error | weakness |
| cwe:CWE-196 | Unsigned to Signed Conversion Error | weakness |
| cwe:CWE-197 | Numeric Truncation Error | weakness |
| cwe:CWE-198 | Use of Incorrect Byte Ordering | weakness |
| cwe:CWE-20 | Improper Input Validation | weakness |
| cwe:CWE-200 | Exposure of Sensitive Information to an Unauthorized Actor | weakness |
| cwe:CWE-201 | Insertion of Sensitive Information Into Sent Data | weakness |
| cwe:CWE-202 | Exposure of Sensitive Information Through Data Queries | weakness |
| cwe:CWE-203 | Observable Discrepancy | weakness |
| cwe:CWE-204 | Observable Response Discrepancy | weakness |
| cwe:CWE-205 | Observable Behavioral Discrepancy | weakness |
| cwe:CWE-206 | Observable Internal Behavioral Discrepancy | weakness |
| cwe:CWE-207 | Observable Behavioral Discrepancy With Equivalent Products | weakness |
| cwe:CWE-208 | Observable Timing Discrepancy | weakness |
| cwe:CWE-209 | Generation of Error Message Containing Sensitive Information | weakness |
| cwe:CWE-210 | Self-generated Error Message Containing Sensitive Information | weakness |
| cwe:CWE-211 | Externally-Generated Error Message Containing Sensitive Information | weakness |
| cwe:CWE-212 | Improper Removal of Sensitive Information Before Storage or Transfer | weakness |
| cwe:CWE-213 | Exposure of Sensitive Information Due to Incompatible Policies | weakness |
| cwe:CWE-214 | Invocation of Process Using Visible Sensitive Information | weakness |
| cwe:CWE-215 | Insertion of Sensitive Information Into Debugging Code | weakness |
| cwe:CWE-216 | DEPRECATED: Containment Errors (Container Errors) | weakness (deprecated) |
| cwe:CWE-217 | DEPRECATED: Failure to Protect Stored Data from Modification | weakness (deprecated) |
| cwe:CWE-218 | DEPRECATED: Failure to provide confidentiality for stored data | weakness (deprecated) |
| cwe:CWE-219 | Storage of File with Sensitive Data Under Web Root | weakness |
| cwe:CWE-22 | Improper Limitation of a Pathname to a Restricted Directory | weakness |
| cwe:CWE-220 | Storage of File With Sensitive Data Under FTP Root | weakness |
| cwe:CWE-221 | Information Loss or Omission | weakness |
| cwe:CWE-222 | Truncation of Security-relevant Information | weakness |
| cwe:CWE-223 | Omission of Security-relevant Information | weakness |
| cwe:CWE-224 | Obscured Security-relevant Information by Alternate Name | weakness |
| cwe:CWE-225 | DEPRECATED: General Information Management Problems | weakness (deprecated) |
| cwe:CWE-226 | Sensitive Information in Resource Not Removed Before Reuse | weakness |
| cwe:CWE-228 | Improper Handling of Syntactically Invalid Structure | weakness |
| cwe:CWE-229 | Improper Handling of Values | weakness |
| cwe:CWE-23 | Relative Path Traversal | weakness |
| cwe:CWE-230 | Improper Handling of Missing Values | weakness |
| cwe:CWE-231 | Improper Handling of Extra Values | weakness |
| cwe:CWE-232 | Improper Handling of Undefined Values | weakness |
| cwe:CWE-233 | Improper Handling of Parameters | weakness |
| cwe:CWE-234 | Failure to Handle Missing Parameter | weakness |
| cwe:CWE-235 | Improper Handling of Extra Parameters | weakness |
| cwe:CWE-236 | Improper Handling of Undefined Parameters | weakness |
| cwe:CWE-237 | Improper Handling of Structural Elements | weakness |
| cwe:CWE-238 | Improper Handling of Incomplete Structural Elements | weakness |
| cwe:CWE-239 | Failure to Handle Incomplete Element | weakness |
| cwe:CWE-24 | Path Traversal: '../filedir' | weakness |
| cwe:CWE-240 | Improper Handling of Inconsistent Structural Elements | weakness |
| cwe:CWE-241 | Improper Handling of Unexpected Data Type | weakness |
| cwe:CWE-242 | Use of Inherently Dangerous Function | weakness |
| cwe:CWE-243 | Creation of chroot Jail Without Changing Working Directory | weakness |
| cwe:CWE-244 | Improper Clearing of Heap Memory Before Release | weakness |
| cwe:CWE-245 | J2EE Bad Practices: Direct Management of Connections | weakness |
| cwe:CWE-246 | J2EE Bad Practices: Direct Use of Sockets | weakness |
| cwe:CWE-247 | DEPRECATED: Reliance on DNS Lookups in a Security Decision | weakness (deprecated) |
| cwe:CWE-248 | Uncaught Exception | weakness |
| cwe:CWE-249 | DEPRECATED: Often Misused: Path Manipulation | weakness (deprecated) |
| cwe:CWE-25 | Path Traversal: '/../filedir' | weakness |
| cwe:CWE-250 | Execution with Unnecessary Privileges | weakness |
| cwe:CWE-252 | Unchecked Return Value | weakness |
| cwe:CWE-253 | Incorrect Check of Function Return Value | weakness |
| cwe:CWE-256 | Plaintext Storage of a Password | weakness |
| cwe:CWE-257 | Storing Passwords in a Recoverable Format | weakness |
| cwe:CWE-258 | Empty Password in Configuration File | weakness |
| cwe:CWE-259 | Use of Hard-coded Password | weakness |
| cwe:CWE-26 | Path Traversal: '/dir/../filename' | weakness |
| cwe:CWE-260 | Password in Configuration File | weakness |
| cwe:CWE-261 | Weak Encoding for Password | weakness |
| cwe:CWE-262 | Not Using Password Aging | weakness |
| cwe:CWE-263 | Password Aging with Long Expiration | weakness |
| cwe:CWE-266 | Incorrect Privilege Assignment | weakness |
| cwe:CWE-267 | Privilege Defined With Unsafe Actions | weakness |
| cwe:CWE-268 | Privilege Chaining | weakness |
| cwe:CWE-269 | Improper Privilege Management | weakness |
| cwe:CWE-27 | Path Traversal: 'dir/../../filename' | weakness |
| cwe:CWE-270 | Privilege Context Switching Error | weakness |
| cwe:CWE-271 | Privilege Dropping / Lowering Errors | weakness |
| cwe:CWE-272 | Least Privilege Violation | weakness |
| cwe:CWE-273 | Improper Check for Dropped Privileges | weakness |
| cwe:CWE-274 | Improper Handling of Insufficient Privileges | weakness |
| cwe:CWE-276 | Incorrect Default Permissions | weakness |
| cwe:CWE-277 | Insecure Inherited Permissions | weakness |
| cwe:CWE-278 | Insecure Preserved Inherited Permissions | weakness |
| cwe:CWE-279 | Incorrect Execution-Assigned Permissions | weakness |
| cwe:CWE-28 | Path Traversal: '..\filedir' | weakness |
| cwe:CWE-280 | Improper Handling of Insufficient Permissions or Privileges | weakness |
| cwe:CWE-281 | Improper Preservation of Permissions | weakness |
| cwe:CWE-282 | Improper Ownership Management | weakness |
| cwe:CWE-283 | Unverified Ownership | weakness |
| cwe:CWE-284 | Improper Access Control | weakness |
| cwe:CWE-285 | Improper Authorization | weakness |
| cwe:CWE-286 | Incorrect User Management | weakness |
| cwe:CWE-287 | Improper Authentication | weakness |
| cwe:CWE-288 | Authentication Bypass Using an Alternate Path or Channel | weakness |
| cwe:CWE-289 | Authentication Bypass by Alternate Name | weakness |
| cwe:CWE-29 | Path Traversal: '\..\filename' | weakness |
| cwe:CWE-290 | Authentication Bypass by Spoofing | weakness |
| cwe:CWE-291 | Reliance on IP Address for Authentication | weakness |
| cwe:CWE-292 | DEPRECATED: Trusting Self-reported DNS Name | weakness (deprecated) |
| cwe:CWE-293 | Using Referer Field for Authentication | weakness |
| cwe:CWE-294 | Authentication Bypass by Capture-replay | weakness |
| cwe:CWE-295 | Improper Certificate Validation | weakness |
| cwe:CWE-296 | Improper Following of a Certificate's Chain of Trust | weakness |
| cwe:CWE-297 | Improper Validation of Certificate with Host Mismatch | weakness |
| cwe:CWE-298 | Improper Validation of Certificate Expiration | weakness |
| cwe:CWE-299 | Improper Check for Certificate Revocation | weakness |
| cwe:CWE-30 | Path Traversal: '\dir\..\filename' | weakness |
| cwe:CWE-300 | Channel Accessible by Non-Endpoint | weakness |
| cwe:CWE-301 | Reflection Attack in an Authentication Protocol | weakness |
| cwe:CWE-302 | Authentication Bypass by Assumed-Immutable Data | weakness |
| cwe:CWE-303 | Incorrect Implementation of Authentication Algorithm | weakness |
| cwe:CWE-304 | Missing Critical Step in Authentication | weakness |
| cwe:CWE-305 | Authentication Bypass by Primary Weakness | weakness |
| cwe:CWE-306 | Missing Authentication for Critical Functionality | weakness |
| cwe:CWE-307 | Improper Restriction of Excessive Authentication Attempts | weakness |
| cwe:CWE-308 | Use of Single-factor Authentication | weakness |
| cwe:CWE-309 | Use of Password System for Primary Authentication | weakness |
| cwe:CWE-31 | Path Traversal: 'dir\..\..\filename' | weakness |
| cwe:CWE-311 | Missing Encryption of Sensitive Data | weakness |
| cwe:CWE-312 | Cleartext Storage of Sensitive Information | weakness |
| cwe:CWE-313 | Cleartext Storage in a File or on Disk | weakness |
| cwe:CWE-314 | Cleartext Storage in the Registry | weakness |
| cwe:CWE-315 | Cleartext Storage of Sensitive Information in a Cookie | weakness |
| cwe:CWE-316 | Cleartext Storage of Sensitive Information in Memory | weakness |
| cwe:CWE-317 | Cleartext Storage of Sensitive Information in GUI | weakness |
| cwe:CWE-318 | Cleartext Storage of Sensitive Information in Executable | weakness |
| cwe:CWE-319 | Cleartext Transmission of Sensitive Information | weakness |
| cwe:CWE-32 | Path Traversal: '...' (Triple Dot) | weakness |
| cwe:CWE-321 | Use of Hard-coded Cryptographic Key | weakness |
| cwe:CWE-322 | Key Exchange without Entity Authentication | weakness |
| cwe:CWE-323 | Reusing a Nonce, Key Pair in Encryption | weakness |
| cwe:CWE-324 | Use of a Key Past its Expiration Date | weakness |
| cwe:CWE-325 | Missing Cryptographic Step | weakness |
| cwe:CWE-326 | Inadequate Encryption Strength | weakness |
| cwe:CWE-327 | Use of a Broken or Risky Cryptographic Algorithm | weakness |
| cwe:CWE-328 | Use of Weak Hash | weakness |
| cwe:CWE-329 | Generation of Predictable IV with CBC Mode | weakness |
| cwe:CWE-33 | Path Traversal: '....' (Multiple Dot) | weakness |
| cwe:CWE-330 | Use of Insufficiently Random Values | weakness |
| cwe:CWE-331 | Insufficient Entropy | weakness |
| cwe:CWE-332 | Insufficient Entropy in PRNG | weakness |
| cwe:CWE-333 | Improper Handling of Insufficient Entropy in TRNG | weakness |
| cwe:CWE-334 | Small Space of Random Values | weakness |
| cwe:CWE-335 | Incorrect Usage of Seeds in Pseudo-Random Number Generator (PRNG) | weakness |
| cwe:CWE-336 | Same Seed in Pseudo-Random Number Generator (PRNG) | weakness |
| cwe:CWE-337 | Predictable Seed in Pseudo-Random Number Generator (PRNG) | weakness |
| cwe:CWE-338 | Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) | weakness |
| cwe:CWE-339 | Small Seed Space in PRNG | weakness |
| cwe:CWE-34 | Path Traversal: '....//' | weakness |
| cwe:CWE-340 | Generation of Predictable Numbers or Identifiers | weakness |
| cwe:CWE-341 | Predictable from Observable State | weakness |
| cwe:CWE-342 | Predictable Exact Value from Previous Values | weakness |
| cwe:CWE-343 | Predictable Value Range from Previous Values | weakness |
| cwe:CWE-344 | Use of Invariant Value in Dynamically Changing Context | weakness |
| cwe:CWE-345 | Insufficient Verification of Data Authenticity | weakness |
| cwe:CWE-346 | Origin Validation Error | weakness |
| cwe:CWE-347 | Improper Verification of Cryptographic Signature | weakness |
| cwe:CWE-348 | Use of Less Trusted Source | weakness |
| cwe:CWE-349 | Acceptance of Extraneous Untrusted Data With Trusted Data | weakness |
| cwe:CWE-35 | Path Traversal: '.../...//' | weakness |
| cwe:CWE-350 | Reliance on Reverse DNS Resolution for a Security-Critical Action | weakness |
| cwe:CWE-351 | Insufficient Type Distinction | weakness |
| cwe:CWE-352 | Cross-Site Request Forgery | weakness |
| cwe:CWE-353 | Missing Support for Integrity Check | weakness |
| cwe:CWE-354 | Improper Validation of Integrity Check Value | weakness |
| cwe:CWE-356 | Missing User Interaction for Potentially Unsafe Action | weakness |
| cwe:CWE-357 | Insufficient UI Warning of Dangerous Operations | weakness |
| cwe:CWE-358 | Improperly Implemented Security Check for Standard | weakness |
| cwe:CWE-359 | Exposure of Private Personal Information to an Unauthorized Actor | weakness |
| cwe:CWE-36 | Absolute Path Traversal | weakness |
| cwe:CWE-360 | Trust of System Event Data | weakness |
| cwe:CWE-362 | Concurrent Execution using Shared Resource with Improper Synchronization | weakness |
| cwe:CWE-363 | Race Condition Enabling Link Following | weakness |
| cwe:CWE-364 | Signal Handler Race Condition | weakness |
| cwe:CWE-365 | DEPRECATED: Race Condition in Switch | weakness (deprecated) |
| cwe:CWE-366 | Race Condition within a Thread | weakness |
| cwe:CWE-367 | Time-of-check Time-of-use (TOCTOU) Race Condition | weakness |
| cwe:CWE-368 | Context Switching Race Condition | weakness |
| cwe:CWE-369 | Divide By Zero | weakness |
| cwe:CWE-37 | Path Traversal: '/absolute/pathname/here' | weakness |
| cwe:CWE-370 | Missing Check for Certificate Revocation after Initial Check | weakness |
| cwe:CWE-372 | Incomplete Internal State Distinction | weakness |
| cwe:CWE-373 | DEPRECATED: State Synchronization Error | weakness (deprecated) |
| cwe:CWE-374 | Passing Mutable Objects to an Untrusted Method | weakness |
| cwe:CWE-375 | Returning a Mutable Object to an Untrusted Caller | weakness |
| cwe:CWE-377 | DEPRECATED: Insecure Temporary File | weakness (deprecated) |
| cwe:CWE-378 | Creation of Temporary File With Insecure Permissions | weakness |
| cwe:CWE-379 | Creation of Temporary File in Directory with Insecure Permissions | weakness |
| cwe:CWE-38 | Path Traversal: '\absolute\pathname\here' | weakness |
| cwe:CWE-382 | J2EE Bad Practices: Use of System.exit() | weakness |
| cwe:CWE-383 | J2EE Bad Practices: Direct Use of Threads | weakness |
| cwe:CWE-384 | Session Fixation | weakness |
| cwe:CWE-385 | Covert Timing Channel | weakness |
| cwe:CWE-386 | Symbolic Name not Mapping to Correct Object | weakness |
| cwe:CWE-39 | Path Traversal: 'C:dirname' | weakness |
| cwe:CWE-390 | Detection of Error Condition Without Action | weakness |
| cwe:CWE-391 | DEPRECATED: Unchecked Error Condition | weakness (deprecated) |
| cwe:CWE-392 | Missing Report of Error Condition | weakness |
| cwe:CWE-393 | Return of Wrong Status Code | weakness |
| cwe:CWE-394 | Unexpected Status Code or Return Value | weakness |
| cwe:CWE-395 | Use of NullPointerException Catch to Detect NULL Pointer Dereference | weakness |
| cwe:CWE-396 | Declaration of Catch for Generic Exception | weakness |
| cwe:CWE-397 | Declaration of Throws for Generic Exception | weakness |
| cwe:CWE-40 | Path Traversal: '\\UNC\share\name\' (Windows UNC Share) | weakness |
| cwe:CWE-400 | Uncontrolled Resource Consumption | weakness |
| cwe:CWE-401 | Missing Release of Memory after Effective Lifetime | weakness |
| cwe:CWE-402 | Transmission of Private Resources into a New Sphere | weakness |
| cwe:CWE-403 | Exposure of File Descriptor to Unintended Control Sphere | weakness |
| cwe:CWE-404 | Improper Resource Shutdown or Release | weakness |
| cwe:CWE-405 | Asymmetric Resource Consumption (Amplification) | weakness |
| cwe:CWE-406 | Insufficient Control of Network Message Volume (Network Amplification) | weakness |
| cwe:CWE-407 | Inefficient Algorithmic Complexity | weakness |
| cwe:CWE-408 | Incorrect Behavior Order: Early Amplification | weakness |
| cwe:CWE-409 | Improper Handling of Highly Compressed Data (Data Amplification) | weakness |
| cwe:CWE-41 | Improper Resolution of Path Equivalence | weakness |
| cwe:CWE-410 | Insufficient Resource Pool | weakness |
| cwe:CWE-412 | Unrestricted Externally Accessible Lock | weakness |
| cwe:CWE-413 | Improper Resource Locking | weakness |
| cwe:CWE-414 | Missing Lock Check | weakness |
| cwe:CWE-415 | Double Free | weakness |
| cwe:CWE-416 | Use After Free | weakness |
| cwe:CWE-419 | Unprotected Primary Channel | weakness |
| cwe:CWE-42 | Path Equivalence: 'filename.' (Trailing Dot) | weakness |
| cwe:CWE-420 | Unprotected Alternate Channel | weakness |
| cwe:CWE-421 | Race Condition During Access to Alternate Channel | weakness |
| cwe:CWE-422 | Unprotected Windows Messaging Channel | weakness |
| cwe:CWE-423 | DEPRECATED: Proxied Trusted Channel | weakness (deprecated) |
| cwe:CWE-424 | Improper Protection of Alternate Path | weakness |
| cwe:CWE-425 | Direct Request | weakness |
| cwe:CWE-426 | Untrusted Search Path | weakness |
| cwe:CWE-427 | Uncontrolled Search Path Element | weakness |
| cwe:CWE-428 | Unquoted Search Path or Element | weakness |
| cwe:CWE-43 | Path Equivalence: 'filename....' (Multiple Trailing Dot) | weakness |
| cwe:CWE-430 | Deployment of Wrong Handler | weakness |
| cwe:CWE-431 | Missing Handler | weakness |
| cwe:CWE-432 | Dangerous Signal Handler not Disabled During Sensitive Operations | weakness |
| cwe:CWE-433 | Unparsed Raw Web Content Delivery | weakness |
| cwe:CWE-434 | Unrestricted Upload of File with Dangerous Type | weakness |
| cwe:CWE-435 | Improper Interaction Between Multiple Correctly-Behaving Entities | weakness |
| cwe:CWE-436 | Interpretation Conflict | weakness |
| cwe:CWE-437 | Incomplete Model of Endpoint Features | weakness |
| cwe:CWE-439 | Behavioral Change in New Version or Environment | weakness |
| cwe:CWE-44 | Path Equivalence: 'file.name' (Internal Dot) | weakness |
| cwe:CWE-440 | Expected Behavior Violation | weakness |
| cwe:CWE-441 | Unintended Proxy or Intermediary | weakness |
| cwe:CWE-443 | DEPRECATED: HTTP response splitting | weakness (deprecated) |
| cwe:CWE-444 | Inconsistent Interpretation of HTTP Requests | weakness |
| cwe:CWE-446 | UI Discrepancy for Security Feature | weakness |
| cwe:CWE-447 | Unimplemented or Unsupported Feature in UI | weakness |
| cwe:CWE-448 | Obsolete Feature in UI | weakness |
| cwe:CWE-449 | The UI Performs the Wrong Action | weakness |
| cwe:CWE-45 | Path Equivalence: 'file...name' (Multiple Internal Dot) | weakness |
| cwe:CWE-450 | Multiple Interpretations of UI Input | weakness |
| cwe:CWE-451 | User Interface (UI) Misrepresentation of Critical Information | weakness |
| cwe:CWE-453 | Insecure Default Variable Initialization | weakness |
| cwe:CWE-454 | External Initialization of Trusted Variables or Data Stores | weakness |
| cwe:CWE-455 | Non-exit on Failed Initialization | weakness |
| cwe:CWE-456 | Missing Initialization of a Variable | weakness |
| cwe:CWE-457 | Use of Uninitialized Variable | weakness |
| cwe:CWE-458 | DEPRECATED: Incorrect Initialization | weakness (deprecated) |
| cwe:CWE-459 | Incomplete Cleanup | weakness |
| cwe:CWE-46 | Path Equivalence: 'filename ' (Trailing Space) | weakness |
| cwe:CWE-460 | Improper Cleanup on Thrown Exception | weakness |
| cwe:CWE-462 | Duplicate Key in Associative List (Alist) | weakness |
| cwe:CWE-463 | Deletion of Data Structure Sentinel | weakness |
| cwe:CWE-464 | Addition of Data Structure Sentinel | weakness |
| cwe:CWE-466 | Return of Pointer Value Outside of Expected Range | weakness |
| cwe:CWE-467 | Use of sizeof() on a Pointer Type | weakness |
| cwe:CWE-468 | Incorrect Pointer Scaling | weakness |
| cwe:CWE-469 | Use of Pointer Subtraction to Determine Size | weakness |
| cwe:CWE-47 | Path Equivalence: ' filename' (Leading Space) | weakness |
| cwe:CWE-470 | Use of Externally-Controlled Input to Select Classes or Code | weakness |
| cwe:CWE-471 | Modification of Assumed-Immutable Data (MAID) | weakness |
| cwe:CWE-472 | External Control of Assumed-Immutable Web Parameter | weakness |
| cwe:CWE-473 | PHP External Variable Modification | weakness |
| cwe:CWE-474 | Use of Function with Inconsistent Implementations | weakness |
| cwe:CWE-475 | Undefined Behavior for Input to API | weakness |
| cwe:CWE-476 | NULL Pointer Dereference | weakness |
| cwe:CWE-477 | Use of Obsolete Function | weakness |
| cwe:CWE-478 | Missing Default Case in Multiple Condition Expression | weakness |
| cwe:CWE-479 | Signal Handler Use of a Non-reentrant Function | weakness |
| cwe:CWE-48 | Path Equivalence: 'file name' (Internal Whitespace) | weakness |
| cwe:CWE-480 | Use of Incorrect Operator | weakness |
| cwe:CWE-481 | Assigning instead of Comparing | weakness |
| cwe:CWE-482 | Comparing instead of Assigning | weakness |
| cwe:CWE-483 | Incorrect Block Delimitation | weakness |
| cwe:CWE-484 | Omitted Break Statement in Switch | weakness |
| cwe:CWE-486 | Comparison of Classes by Name | weakness |
| cwe:CWE-487 | Reliance on Package-level Scope | weakness |
| cwe:CWE-488 | Exposure of Data Element to Wrong Session | weakness |
| cwe:CWE-489 | Active Debug Code | weakness |
| cwe:CWE-49 | Path Equivalence: 'filename/' (Trailing Slash) | weakness |
| cwe:CWE-491 | Public cloneable() Method Without Final | weakness |
| cwe:CWE-492 | Use of Inner Class Containing Sensitive Data | weakness |
| cwe:CWE-493 | Critical Public Variable Without Final Modifier | weakness |
| cwe:CWE-494 | Download of Code Without Integrity Check | weakness |
| cwe:CWE-495 | Private Data Structure Returned From A Public Method | weakness |
| cwe:CWE-496 | Public Data Assigned to Private Array-Typed Field | weakness |
| cwe:CWE-497 | Exposure of Sensitive System Information to an Unauthorized Control Sphere | weakness |
| cwe:CWE-498 | Cloneable Class Containing Sensitive Information | weakness |
| cwe:CWE-499 | Serializable Class Containing Sensitive Data | weakness |
| cwe:CWE-5 | J2EE Misconfiguration: Data Transmission Without Encryption | weakness |
| cwe:CWE-50 | Path Equivalence: '//multiple/leading/slash' | weakness |
| cwe:CWE-500 | Public Static Field Not Marked Final | weakness |
| cwe:CWE-501 | Trust Boundary Violation | weakness |
| cwe:CWE-502 | Deserialization of Untrusted Data | weakness |
| cwe:CWE-506 | Embedded Malicious Code | weakness |
| cwe:CWE-507 | Trojan Horse | weakness |
| cwe:CWE-508 | Non-Replicating Malicious Code | weakness |
| cwe:CWE-509 | Replicating Malicious Code (Virus or Worm) | weakness |
| cwe:CWE-51 | Path Equivalence: '/multiple//internal/slash' | weakness |
| cwe:CWE-510 | Trapdoor | weakness |
| cwe:CWE-511 | Logic/Time Bomb | weakness |
| cwe:CWE-512 | Spyware | weakness |
| cwe:CWE-514 | Covert Channel | weakness |
| cwe:CWE-515 | Covert Storage Channel | weakness |
| cwe:CWE-516 | DEPRECATED: Covert Timing Channel | weakness (deprecated) |
| cwe:CWE-52 | Path Equivalence: '/multiple/trailing/slash//' | weakness |
| cwe:CWE-520 | .NET Misconfiguration: Use of Impersonation | weakness |
| cwe:CWE-521 | Weak Password Requirements | weakness |
| cwe:CWE-522 | Insufficiently Protected Credentials | weakness |
| cwe:CWE-523 | Unprotected Transport of Credentials | weakness |
| cwe:CWE-524 | Use of Cache Containing Sensitive Information | weakness |
| cwe:CWE-525 | Use of Web Browser Cache Containing Sensitive Information | weakness |
| cwe:CWE-526 | Cleartext Storage of Sensitive Information in an Environment Variable | weakness |
| cwe:CWE-527 | Exposure of Version-Control Repository to an Unauthorized Control Sphere | weakness |
| cwe:CWE-528 | Exposure of Core Dump File to an Unauthorized Control Sphere | weakness |
| cwe:CWE-529 | Exposure of Access Control List Files to an Unauthorized Control Sphere | weakness |
| cwe:CWE-53 | Path Equivalence: '\multiple\\internal\backslash' | weakness |
| cwe:CWE-530 | Exposure of Backup File to an Unauthorized Control Sphere | weakness |
| cwe:CWE-531 | Inclusion of Sensitive Information in Test Code | weakness |
| cwe:CWE-532 | Insertion of Sensitive Information into Log File | weakness |
| cwe:CWE-533 | DEPRECATED: Information Exposure Through Server Log Files | weakness (deprecated) |
| cwe:CWE-534 | DEPRECATED: Information Exposure Through Debug Log Files | weakness (deprecated) |
| cwe:CWE-535 | Exposure of Information Through Shell Error Message | weakness |
| cwe:CWE-536 | Servlet Runtime Error Message Containing Sensitive Information | weakness |
| cwe:CWE-537 | Java Runtime Error Message Containing Sensitive Information | weakness |
| cwe:CWE-538 | Insertion of Sensitive Information into Externally-Accessible File or Directory | weakness |
| cwe:CWE-539 | Use of Persistent Cookies Containing Sensitive Information | weakness |
| cwe:CWE-54 | Path Equivalence: 'filedir\' (Trailing Backslash) | weakness |
| cwe:CWE-540 | Inclusion of Sensitive Information in Source Code | weakness |
| cwe:CWE-541 | Inclusion of Sensitive Information in an Include File | weakness |
| cwe:CWE-542 | DEPRECATED: Information Exposure Through Cleanup Log Files | weakness (deprecated) |
| cwe:CWE-543 | Use of Singleton Pattern Without Synchronization in a Multithreaded Context | weakness |
| cwe:CWE-544 | Missing Standardized Error Handling Mechanism | weakness |
| cwe:CWE-545 | DEPRECATED: Use of Dynamic Class Loading | weakness (deprecated) |
| cwe:CWE-546 | Suspicious Comment | weakness |
| cwe:CWE-547 | Use of Hard-coded, Security-relevant Constants | weakness |
| cwe:CWE-548 | Exposure of Information Through Directory Listing | weakness |
| cwe:CWE-549 | Missing Password Field Masking | weakness |
| cwe:CWE-55 | Path Equivalence: '/./' (Single Dot Directory) | weakness |
| cwe:CWE-550 | Server-generated Error Message Containing Sensitive Information | weakness |
| cwe:CWE-551 | Incorrect Behavior Order: Authorization Before Parsing and Canonicalization | weakness |
| cwe:CWE-552 | Files or Directories Accessible to External Parties | weakness |
| cwe:CWE-553 | Command Shell in Externally Accessible Directory | weakness |
| cwe:CWE-554 | ASP.NET Misconfiguration: Not Using Input Validation Framework | weakness |
| cwe:CWE-555 | J2EE Misconfiguration: Plaintext Password in Configuration File | weakness |
| cwe:CWE-556 | ASP.NET Misconfiguration: Use of Identity Impersonation | weakness |
| cwe:CWE-558 | Use of getlogin() in Multithreaded Application | weakness |
| cwe:CWE-56 | Path Equivalence: 'filedir*' (Wildcard) | weakness |
| cwe:CWE-560 | Use of umask() with chmod-style Argument | weakness |
| cwe:CWE-561 | Dead Code | weakness |
| cwe:CWE-562 | Return of Stack Variable Address | weakness |
| cwe:CWE-563 | Assignment to Variable without Use | weakness |
| cwe:CWE-564 | Use of Hibernate with HQL/SQL Query String Containing External Input | weakness |
| cwe:CWE-565 | Reliance on Cookies without Validation and Integrity Checking | weakness |
| cwe:CWE-566 | Authorization Bypass Through User-Controlled SQL Primary Key | weakness |
| cwe:CWE-567 | Unsynchronized Access to Shared Data in a Multithreaded Context | weakness |
| cwe:CWE-568 | finalize() Method Without super.finalize() | weakness |
| cwe:CWE-57 | Path Equivalence: 'fakedir/../realdir/filename' | weakness |
| cwe:CWE-570 | Expression is Always False | weakness |
| cwe:CWE-571 | Expression is Always True | weakness |
| cwe:CWE-572 | Call to Thread run() instead of start() | weakness |
| cwe:CWE-573 | Improper Following of Specification by Caller | weakness |
| cwe:CWE-574 | EJB Bad Practices: Use of Synchronization Primitives | weakness |
| cwe:CWE-575 | EJB Bad Practices: Use of AWT Swing | weakness |
| cwe:CWE-576 | EJB Bad Practices: Use of Java I/O | weakness |
| cwe:CWE-577 | EJB Bad Practices: Use of Sockets | weakness |
| cwe:CWE-578 | EJB Bad Practices: Use of Class Loader | weakness |
| cwe:CWE-579 | J2EE Bad Practices: Non-serializable Object Stored in Session | weakness |
| cwe:CWE-58 | Path Equivalence: Windows 8.3 Filename | weakness |
| cwe:CWE-580 | clone() Method Without super.clone() | weakness |
| cwe:CWE-581 | Object Model Violation: Just One of Equals and Hashcode Defined | weakness |
| cwe:CWE-582 | Array Declared Public, Final, and Static | weakness |
| cwe:CWE-583 | finalize() Method Declared Public | weakness |
| cwe:CWE-584 | Return Inside Finally Block | weakness |
| cwe:CWE-585 | Empty Synchronized Block | weakness |
| cwe:CWE-586 | Explicit Call to Finalize() | weakness |
| cwe:CWE-587 | Assignment of a Fixed Address to a Pointer | weakness |
| cwe:CWE-588 | Attempt to Access Child of a Non-structure Pointer | weakness |
| cwe:CWE-589 | Call to Non-ubiquitous API | weakness |
| cwe:CWE-59 | Improper Link Resolution Before File Access | weakness |
| cwe:CWE-590 | Free of Memory not on the Heap | weakness |
| cwe:CWE-591 | Sensitive Data Storage in Improperly Locked Memory | weakness |
| cwe:CWE-592 | DEPRECATED: Authentication Bypass Issues | weakness (deprecated) |
| cwe:CWE-593 | Authentication Bypass: OpenSSL CTX Object Modified after SSL Objects are Created | weakness |
| cwe:CWE-594 | J2EE Framework: Saving Unserializable Objects to Disk | weakness |
| cwe:CWE-595 | Comparison of Object References Instead of Object Contents | weakness |
| cwe:CWE-596 | DEPRECATED: Incorrect Semantic Object Comparison | weakness (deprecated) |
| cwe:CWE-597 | Use of Wrong Operator in String Comparison | weakness |
| cwe:CWE-598 | Use of HTTP Request With Sensitive Query String | weakness |
| cwe:CWE-599 | Missing Validation of OpenSSL Certificate | weakness |
| cwe:CWE-6 | J2EE Misconfiguration: Insufficient Session-ID Length | weakness |
| cwe:CWE-600 | Uncaught Exception in Servlet | weakness |
| cwe:CWE-601 | URL Redirection to Untrusted Site | weakness |
| cwe:CWE-602 | Client-Side Enforcement of Server-Side Security | weakness |
| cwe:CWE-603 | Use of Client-Side Authentication | weakness |
| cwe:CWE-605 | Multiple Binds to the Same Port | weakness |
| cwe:CWE-606 | Unchecked Input for Loop Condition | weakness |
| cwe:CWE-607 | Public Static Final Field References Mutable Object | weakness |
| cwe:CWE-608 | Struts: Non-private Field in ActionForm Class | weakness |
| cwe:CWE-609 | Double-Checked Locking | weakness |
| cwe:CWE-61 | UNIX Symbolic Link (Symlink) Following | weakness |
| cwe:CWE-610 | Externally Controlled Reference to a Resource in Another Sphere | weakness |
| cwe:CWE-611 | Improper Restriction of XML External Entity Reference | weakness |
| cwe:CWE-612 | Improper Authorization of Index Containing Sensitive Information | weakness |
| cwe:CWE-613 | DEPRECATED: Insufficient Session Expiration | weakness (deprecated) |
| cwe:CWE-614 | Sensitive Cookie in HTTPS Session Without 'Secure' Attribute | weakness |
| cwe:CWE-615 | Inclusion of Sensitive Information in Source Code Comments | weakness |
| cwe:CWE-616 | Incomplete Identification of Uploaded File Variables (PHP) | weakness |
| cwe:CWE-617 | Reachable Assertion | weakness |
| cwe:CWE-618 | Exposed Unsafe ActiveX Method | weakness |
| cwe:CWE-619 | Dangling Database Cursor | weakness |
| cwe:CWE-62 | UNIX Hard Link | weakness |
| cwe:CWE-620 | Unverified Password Change | weakness |
| cwe:CWE-621 | Variable Extraction Error | weakness |
| cwe:CWE-622 | Improper Validation of Function Hook Arguments | weakness |
| cwe:CWE-623 | Unsafe ActiveX Control Marked Safe For Scripting | weakness |
| cwe:CWE-624 | Executable Regular Expression Error | weakness |
| cwe:CWE-625 | Permissive Regular Expression | weakness |
| cwe:CWE-626 | Null Byte Interaction Error (Poison Null Byte) | weakness |
| cwe:CWE-627 | Dynamic Variable Evaluation | weakness |
| cwe:CWE-628 | Function Call with Incorrectly Specified Arguments | weakness |
| cwe:CWE-636 | Not Failing Securely | weakness |
| cwe:CWE-637 | Unnecessary Complexity in Protection Mechanism (Not Using 'Economy of Mechanism') | weakness |
| cwe:CWE-638 | Not Using Complete Mediation | weakness |
| cwe:CWE-639 | Authorization Bypass Through User-Controlled Key | weakness |
| cwe:CWE-64 | Windows Shortcut Following (.LNK) | weakness |
| cwe:CWE-640 | Weak Password Recovery Mechanism for Forgotten Password | weakness |
| cwe:CWE-641 | Improper Restriction of Names for Files and Other Resources | weakness |
| cwe:CWE-642 | External Control of Critical State Data | weakness |
| cwe:CWE-643 | Improper Neutralization of Data within XPath Expressions | weakness |
| cwe:CWE-644 | Improper Neutralization of HTTP Headers for Scripting Syntax | weakness |
| cwe:CWE-645 | Overly Restrictive Account Lockout Mechanism | weakness |
| cwe:CWE-646 | Reliance on File Name or Extension of Externally-Supplied File | weakness |
| cwe:CWE-647 | Use of Non-Canonical URL Paths for Authorization Decisions | weakness |
| cwe:CWE-648 | Incorrect Use of Privileged APIs | weakness |
| cwe:CWE-649 | Reliance on Obfuscation or Encryption of Security-Relevant Inputs without Integrity Checking | weakness |
| cwe:CWE-65 | Windows Hard Link | weakness |
| cwe:CWE-650 | Trusting HTTP Permission Methods on the Server Side | weakness |
| cwe:CWE-651 | Exposure of WSDL File Containing Sensitive Information | weakness |
| cwe:CWE-652 | Improper Neutralization of Data within XQuery Expressions | weakness |
| cwe:CWE-653 | Improper Isolation or Compartmentalization | weakness |
| cwe:CWE-654 | Reliance on a Single Factor in a Security Decision | weakness |
| cwe:CWE-655 | Insufficient Psychological Acceptability | weakness |
| cwe:CWE-656 | Reliance on Security Through Obscurity | weakness |
| cwe:CWE-657 | Violation of Secure Design Principles | weakness |
| cwe:CWE-66 | Improper Handling of File Names that Identify Virtual Resources | weakness |
| cwe:CWE-662 | Improper Synchronization | weakness |
| cwe:CWE-663 | Use of a Non-reentrant Function in a Concurrent Context | weakness |
| cwe:CWE-664 | Improper Control of a Resource Through its Lifetime | weakness |
| cwe:CWE-665 | Improper Initialization | weakness |
| cwe:CWE-666 | Operation on Resource in Wrong Phase of Lifetime | weakness |
| cwe:CWE-667 | Improper Locking | weakness |
| cwe:CWE-668 | Exposure of Resource to Wrong Sphere | weakness |
| cwe:CWE-669 | Incorrect Resource Transfer Between Spheres | weakness |
| cwe:CWE-67 | Improper Handling of Windows Device Names | weakness |
| cwe:CWE-670 | Always-Incorrect Control Flow Implementation | weakness |
| cwe:CWE-671 | Lack of Administrator Control over Security | weakness |
| cwe:CWE-672 | Operation on a Resource after Expiration or Release | weakness |
| cwe:CWE-673 | External Influence of Sphere Definition | weakness |
| cwe:CWE-674 | Uncontrolled Recursion | weakness |
| cwe:CWE-675 | Multiple Operations on Resource in Single-Operation Context | weakness |
| cwe:CWE-676 | Use of Potentially Dangerous Function | weakness |
| cwe:CWE-680 | Integer Overflow to Buffer Overflow | weakness |
| cwe:CWE-681 | Incorrect Conversion between Numeric Types | weakness |
| cwe:CWE-682 | Incorrect Calculation | weakness |
| cwe:CWE-683 | Function Call With Incorrect Order of Arguments | weakness |
| cwe:CWE-684 | Incorrect Provision of Specified Functionality | weakness |
| cwe:CWE-685 | Function Call With Incorrect Number of Arguments | weakness |
| cwe:CWE-686 | Function Call With Incorrect Argument Type | weakness |
| cwe:CWE-687 | Function Call With Incorrectly Specified Argument Value | weakness |
| cwe:CWE-688 | Function Call With Incorrect Variable or Reference as Argument | weakness |
| cwe:CWE-689 | Permission Race Condition During Resource Copy | weakness |
| cwe:CWE-69 | Improper Handling of Windows ::DATA Alternate Data Stream | weakness |
| cwe:CWE-690 | Unchecked Return Value to NULL Pointer Dereference | weakness |
| cwe:CWE-691 | Insufficient Control Flow Management | weakness |
| cwe:CWE-692 | Incomplete Denylist to Cross-Site Scripting | weakness |
| cwe:CWE-693 | Protection Mechanism Failure | weakness |
| cwe:CWE-694 | Use of Multiple Resources with Duplicate Identifier | weakness |
| cwe:CWE-695 | Use of Low-Level Functionality | weakness |
| cwe:CWE-696 | Incorrect Behavior Order | weakness |
| cwe:CWE-697 | Incorrect Comparison | weakness |
| cwe:CWE-698 | Execution After Redirect (EAR) | weakness |
| cwe:CWE-7 | J2EE Misconfiguration: Missing Custom Error Page | weakness |
| cwe:CWE-703 | Improper Check or Handling of Exceptional Conditions | weakness |
| cwe:CWE-704 | Incorrect Type Conversion or Cast | weakness |
| cwe:CWE-705 | Incorrect Control Flow Scoping | weakness |
| cwe:CWE-706 | Use of Incorrectly-Resolved Name or Reference | weakness |
| cwe:CWE-707 | Improper Neutralization | weakness |
| cwe:CWE-708 | Incorrect Ownership Assignment | weakness |
| cwe:CWE-71 | DEPRECATED: Apple '.DS_Store' | weakness (deprecated) |
| cwe:CWE-710 | Improper Adherence to Coding Standards | weakness |
| cwe:CWE-72 | Improper Handling of Apple HFS+ Alternate Data Stream Path | weakness |
| cwe:CWE-73 | External Control of File Name or Path | weakness |
| cwe:CWE-732 | Incorrect Permission Assignment for Critical Resource | weakness |
| cwe:CWE-733 | Compiler Optimization Removal or Modification of Security-critical Code | weakness |
| cwe:CWE-74 | Improper Neutralization of Special Elements in Output Used by a Downstream Component | weakness |
| cwe:CWE-749 | Exposed Dangerous Method or Function | weakness |
| cwe:CWE-75 | Failure to Sanitize Special Elements into a Different Plane | weakness |
| cwe:CWE-754 | Improper Check for Unusual or Exceptional Conditions | weakness |
| cwe:CWE-755 | Improper Handling of Exceptional Conditions | weakness |
| cwe:CWE-756 | Missing Custom Error Page | weakness |
| cwe:CWE-757 | Selection of Less-Secure Algorithm During Negotiation | weakness |
| cwe:CWE-758 | Reliance on Undefined, Unspecified, or Implementation-Defined Behavior | weakness |
| cwe:CWE-759 | Use of a One-Way Hash without a Salt | weakness |
| cwe:CWE-76 | Improper Neutralization of Equivalent Special Elements | weakness |
| cwe:CWE-760 | Use of a One-Way Hash with a Predictable Salt | weakness |
| cwe:CWE-761 | Free of Pointer not at Start of Buffer | weakness |
| cwe:CWE-762 | Mismatched Memory Management Routines | weakness |
| cwe:CWE-763 | Release of Invalid Pointer or Reference | weakness |
| cwe:CWE-764 | Multiple Locks of a Critical Resource | weakness |
| cwe:CWE-765 | Multiple Unlocks of a Critical Resource | weakness |
| cwe:CWE-766 | Critical Data Element Declared Public | weakness |
| cwe:CWE-767 | Access to Critical Private Variable via Public Method | weakness |
| cwe:CWE-768 | Incorrect Short Circuit Evaluation | weakness |
| cwe:CWE-769 | DEPRECATED: Uncontrolled File Descriptor Consumption | weakness (deprecated) |
| cwe:CWE-77 | Improper Neutralization of Special Elements used in a Command | weakness |
| cwe:CWE-770 | Allocation of Resources Without Limits or Throttling | weakness |
| cwe:CWE-771 | Missing Reference to Active Allocated Resource | weakness |
| cwe:CWE-772 | Missing Release of Resource after Effective Lifetime | weakness |
| cwe:CWE-773 | Missing Reference to Active File Descriptor or Handle | weakness |
| cwe:CWE-774 | Allocation of File Descriptors or Handles Without Limits or Throttling | weakness |
| cwe:CWE-775 | Missing Release of File Descriptor or Handle after Effective Lifetime | weakness |
| cwe:CWE-776 | Improper Restriction of Recursive Entity References in DTDs | weakness |
| cwe:CWE-777 | Regular Expression without Anchors | weakness |
| cwe:CWE-778 | Insufficient Logging | weakness |
| cwe:CWE-779 | Logging of Excessive Data | weakness |
| cwe:CWE-78 | Improper Neutralization of Special Elements used in an OS Command | weakness |
| cwe:CWE-780 | Use of RSA Algorithm without OAEP | weakness |
| cwe:CWE-781 | Improper Address Validation in IOCTL with METHOD_NEITHER I/O Control Code | weakness |
| cwe:CWE-782 | Exposed IOCTL with Insufficient Access Control | weakness |
| cwe:CWE-783 | Operator Precedence Logic Error | weakness |
| cwe:CWE-784 | Reliance on Cookies without Validation and Integrity Checking in a Security Decision | weakness |
| cwe:CWE-785 | Use of Path Manipulation Function without Maximum-sized Buffer | weakness |
| cwe:CWE-786 | Access of Memory Location Before Start of Buffer | weakness |
| cwe:CWE-787 | Out-of-bounds Write | weakness |
| cwe:CWE-788 | Access of Memory Location After End of Buffer | weakness |
| cwe:CWE-789 | Memory Allocation with Excessive Size Value | weakness |
| cwe:CWE-79 | Improper Neutralization of Input During Web Page Generation | weakness |
| cwe:CWE-790 | Improper Filtering of Special Elements | weakness |
| cwe:CWE-791 | Incomplete Filtering of Special Elements | weakness |
| cwe:CWE-792 | Incomplete Filtering of One or More Instances of Special Elements | weakness |
| cwe:CWE-793 | Only Filtering One Instance of a Special Element | weakness |
| cwe:CWE-794 | Incomplete Filtering of Multiple Instances of Special Elements | weakness |
| cwe:CWE-795 | Only Filtering Special Elements at a Specified Location | weakness |
| cwe:CWE-796 | Only Filtering Special Elements Relative to a Marker | weakness |
| cwe:CWE-797 | Only Filtering Special Elements at an Absolute Position | weakness |
| cwe:CWE-798 | Use of Hard-coded Credentials | weakness |
| cwe:CWE-799 | Improper Control of Interaction Frequency | weakness |
| cwe:CWE-8 | J2EE Misconfiguration: Entity Bean Declared Remote | weakness |
| cwe:CWE-80 | Improper Neutralization of Script-Related HTML Tags in a Web Page | weakness |
| cwe:CWE-804 | Guessable CAPTCHA | weakness |
| cwe:CWE-805 | Buffer Access with Incorrect Length Value | weakness |
| cwe:CWE-806 | Buffer Access Using Size of Source Buffer | weakness |
| cwe:CWE-807 | Reliance on Untrusted Inputs in a Security Decision | weakness |
| cwe:CWE-81 | Improper Neutralization of Script in an Error Message Web Page | weakness |
| cwe:CWE-82 | Improper Neutralization of Script in Attributes of IMG Tags in a Web Page | weakness |
| cwe:CWE-820 | Missing Synchronization | weakness |
| cwe:CWE-821 | Incorrect Synchronization | weakness |
| cwe:CWE-822 | Untrusted Pointer Dereference | weakness |
| cwe:CWE-823 | Use of Out-of-range Pointer Offset | weakness |
| cwe:CWE-824 | Access of Uninitialized Pointer | weakness |
| cwe:CWE-825 | Expired Pointer Dereference | weakness |
| cwe:CWE-826 | Premature Release of Resource During Expected Lifetime | weakness |
| cwe:CWE-827 | Improper Control of Document Type Definition | weakness |
| cwe:CWE-828 | Signal Handler with Functionality that is not Asynchronous-Safe | weakness |
| cwe:CWE-829 | Inclusion of Functionality from Untrusted Control Sphere | weakness |
| cwe:CWE-83 | Improper Neutralization of Script in Attributes in a Web Page | weakness |
| cwe:CWE-830 | Inclusion of Web Functionality from an Untrusted Source | weakness |
| cwe:CWE-831 | Signal Handler Function Associated with Multiple Signals | weakness |
| cwe:CWE-832 | Unlock of a Resource that is not Locked | weakness |
| cwe:CWE-833 | Deadlock | weakness |
| cwe:CWE-834 | Excessive Iteration | weakness |
| cwe:CWE-835 | Loop with Unreachable Exit Condition | weakness |
| cwe:CWE-836 | Use of Password Hash Instead of Password for Authentication | weakness |
| cwe:CWE-837 | Improper Enforcement of a Single, Unique Action | weakness |
| cwe:CWE-838 | Inappropriate Encoding for Output Context | weakness |
| cwe:CWE-839 | Numeric Range Comparison Without Minimum Check | weakness |
| cwe:CWE-84 | Improper Neutralization of Encoded URI Schemes in a Web Page | weakness |
| cwe:CWE-841 | Improper Enforcement of Behavioral Workflow | weakness |
| cwe:CWE-842 | Placement of User into Incorrect Group | weakness |
| cwe:CWE-843 | Access of Resource Using Incompatible Type | weakness |
| cwe:CWE-85 | Doubled Character XSS Manipulations | weakness |
| cwe:CWE-86 | Improper Neutralization of Invalid Characters in Identifiers in Web Pages | weakness |
| cwe:CWE-862 | Missing Authorization | weakness |
| cwe:CWE-863 | Incorrect Authorization | weakness |
| cwe:CWE-87 | Improper Neutralization of Alternate XSS Syntax | weakness |
| cwe:CWE-88 | Improper Neutralization of Argument Delimiters in a Command | weakness |
| cwe:CWE-89 | Improper Neutralization of Special Elements used in an SQL Command | weakness |
| cwe:CWE-9 | J2EE Misconfiguration: Weak Access Permissions for EJB Methods | weakness |
| cwe:CWE-90 | Improper Neutralization of Special Elements used in an LDAP Query | weakness |
| cwe:CWE-908 | Use of Uninitialized Resource | weakness |
| cwe:CWE-909 | Missing Initialization of Resource | weakness |
| cwe:CWE-91 | XML Injection | weakness |
| cwe:CWE-910 | Use of Expired File Descriptor | weakness |
| cwe:CWE-911 | Improper Update of Reference Count | weakness |
| cwe:CWE-912 | Hidden Functionality | weakness |
| cwe:CWE-913 | Improper Control of Dynamically-Managed Code Resources | weakness |
| cwe:CWE-914 | Improper Control of Dynamically-Identified Variables | weakness |
| cwe:CWE-915 | Improperly Controlled Modification of Dynamically-Determined Object Attributes | weakness |
| cwe:CWE-916 | Use of Password Hash With Insufficient Computational Effort | weakness |
| cwe:CWE-917 | Improper Neutralization of Special Elements used in an Expression Language Statement | weakness |
| cwe:CWE-918 | Server-Side Request Forgery | weakness |
| cwe:CWE-92 | DEPRECATED: Improper Sanitization of Custom Special Characters | weakness (deprecated) |
| cwe:CWE-920 | Improper Restriction of Power Consumption | weakness |
| cwe:CWE-921 | Storage of Sensitive Data in a Mechanism without Access Control | weakness |
| cwe:CWE-922 | Insecure Storage of Sensitive Information | weakness |
| cwe:CWE-923 | Improper Restriction of Communication Channel to Intended Endpoints | weakness |
| cwe:CWE-924 | Improper Enforcement of Message Integrity During Transmission in a Communication Channel | weakness |
| cwe:CWE-925 | Improper Verification of Intent by Broadcast Receiver | weakness |
| cwe:CWE-926 | Improper Export of Android Application Components | weakness |
| cwe:CWE-927 | Use of Implicit Intent for Sensitive Communication | weakness |
| cwe:CWE-93 | Improper Neutralization of CRLF Sequences | weakness |
| cwe:CWE-939 | Improper Authorization in Handler for Custom URL Scheme | weakness |
| cwe:CWE-94 | Improper Control of Generation of Code | weakness |
| cwe:CWE-940 | Improper Verification of Source of a Communication Channel | weakness |
| cwe:CWE-941 | Incorrectly Specified Destination in a Communication Channel | weakness |
| cwe:CWE-942 | Permissive Cross-domain Security Policy with Untrusted Domains | weakness |
| cwe:CWE-943 | Improper Neutralization of Special Elements in Data Query Logic | weakness |
| cwe:CWE-95 | Improper Neutralization of Directives in Dynamically Evaluated Code | weakness |
| cwe:CWE-96 | Improper Neutralization of Directives in Statically Saved Code | weakness |
| cwe:CWE-97 | Improper Neutralization of Server-Side Includes (SSI) Within a Web Page | weakness |
| cwe:CWE-98 | Improper Control of Filename for Include/Require Statement in PHP Program | weakness |
| cwe:CWE-99 | Improper Control of Resource Identifiers | weakness |

## ISO/IEC 27001

| ID | Name | Kind |
| --- | --- | --- |
| iso27001:ISO-IEC-27001:2022 | Information security management system | framework_reference |

## MITRE ATLAS

| ID | Name | Kind |
| --- | --- | --- |
| mitre-atlas:AML.M0000 | Limit Public Release of Information | mitigation |
| mitre-atlas:AML.M0001 | Limit Model Artifact Release | mitigation |
| mitre-atlas:AML.M0002 | Predictive AI Output Obfuscation | mitigation |
| mitre-atlas:AML.M0003 | Predictive AI Model Hardening | mitigation |
| mitre-atlas:AML.M0004 | Limit AI Service Query Volume and Rate | mitigation |
| mitre-atlas:AML.M0005 | Control Access to AI Models and Data at Rest | mitigation |
| mitre-atlas:AML.M0006 | Predictive AI Ensembles | mitigation |
| mitre-atlas:AML.M0007 | Sanitize Training Data | mitigation |
| mitre-atlas:AML.M0008 | Validate AI Model | mitigation |
| mitre-atlas:AML.M0009 | Predictive AI Multi-Sensor Fusion | mitigation |
| mitre-atlas:AML.M0010 | Predictive AI Input Restoration | mitigation |
| mitre-atlas:AML.M0011 | Restrict Library Loading | mitigation |
| mitre-atlas:AML.M0012 | Encrypt Sensitive Information | mitigation |
| mitre-atlas:AML.M0013 | Code Signing | mitigation |
| mitre-atlas:AML.M0014 | Verify AI Artifacts | mitigation |
| mitre-atlas:AML.M0015 | Predictive AI Adversarial Input Detection | mitigation |
| mitre-atlas:AML.M0016 | Vulnerability Scanning | mitigation |
| mitre-atlas:AML.M0017 | AI Model Distribution Methods | mitigation |
| mitre-atlas:AML.M0018 | User Training | mitigation |
| mitre-atlas:AML.M0019 | Control Access to AI Models and Data in Production | mitigation |
| mitre-atlas:AML.M0020 | Generative AI Guardrails | mitigation |
| mitre-atlas:AML.M0021 | Generative AI Guidelines | mitigation |
| mitre-atlas:AML.M0022 | Generative AI Model Alignment | mitigation |
| mitre-atlas:AML.M0023 | Maintain an AI Bill of Materials | mitigation |
| mitre-atlas:AML.M0024 | AI Telemetry Logging and Monitoring | mitigation |
| mitre-atlas:AML.M0025 | Maintain AI Dataset Provenance | mitigation |
| mitre-atlas:AML.M0026 | Manage AI Agent Service Access | mitigation |
| mitre-atlas:AML.M0027 | Manage User-Delegated AI Agent Access | mitigation |
| mitre-atlas:AML.M0028 | Enforce Access Controls for AI Agent Tools | mitigation |
| mitre-atlas:AML.M0029 | Human In-the-Loop for AI Agent Actions | mitigation |
| mitre-atlas:AML.M0030 | Restrict AI Agent Tool Invocation on Untrusted Data | mitigation |
| mitre-atlas:AML.M0031 | Memory Hardening | mitigation |
| mitre-atlas:AML.M0032 | Segmentation of AI Agent Components | mitigation |
| mitre-atlas:AML.M0033 | Input and Output Validation for AI Agent Components | mitigation |
| mitre-atlas:AML.M0034 | Deepfake Detection | mitigation |
| mitre-atlas:AML.M0035 | AI Red Team | mitigation |
| mitre-atlas:AML.M0036 | Limit AI Workload Resource Consumption | mitigation |
| mitre-atlas:AML.M0037 | AI Agent Authority Expansion Controls | mitigation |
| mitre-atlas:AML.M0038 | AI Agent Scope Drift Detection | mitigation |
| mitre-atlas:AML.M0039 | AI Honeypots | mitigation |
| mitre-atlas:AML.M0040 | Adaptive AI Response Degradation | mitigation |
| mitre-atlas:AML.M0041 | Privacy-Preserving AI Training and Inference | mitigation |
| mitre-atlas:AML.M0042 | Threat Intelligence Program | mitigation |
| mitre-atlas:AML.M0043 | AI Agent External Resource Lifecycle Management | mitigation |
| mitre-atlas:AML.T0000 | Search Open Technical Databases | technique |
| mitre-atlas:AML.T0000.000 | Journals and Conference Proceedings | technique |
| mitre-atlas:AML.T0000.001 | Pre-Print Repositories | technique |
| mitre-atlas:AML.T0000.002 | Technical Blogs | technique |
| mitre-atlas:AML.T0000.003 | Scan Databases | technique |
| mitre-atlas:AML.T0001 | Search Open AI Vulnerability Analysis | technique |
| mitre-atlas:AML.T0002 | Acquire Public AI Artifacts | technique |
| mitre-atlas:AML.T0002.000 | Datasets | technique |
| mitre-atlas:AML.T0002.001 | Models | technique |
| mitre-atlas:AML.T0002.002 | AI Agent Configuration | technique |
| mitre-atlas:AML.T0003 | Search Victim-Owned Websites | technique |
| mitre-atlas:AML.T0004 | Search Application Repositories | technique |
| mitre-atlas:AML.T0005 | Replicate AI Model Behavior | technique |
| mitre-atlas:AML.T0005.000 | Replicate Behavior from Gathered AI Artifacts | technique |
| mitre-atlas:AML.T0005.001 | Replicate Behavior from Model Outputs | technique |
| mitre-atlas:AML.T0005.002 | Adapt Existing Model to Replicate Behavior | technique |
| mitre-atlas:AML.T0006 | Active Scanning | technique |
| mitre-atlas:AML.T0006.000 | Enumerate Hosted AI Resources | technique |
| mitre-atlas:AML.T0006.001 | Query Platform Metadata APIs | technique |
| mitre-atlas:AML.T0006.002 | Scan for Exposed AI Infrastructure | technique |
| mitre-atlas:AML.T0006.003 | Probe AI Agent Trigger Channels | technique |
| mitre-atlas:AML.T0007 | Discover AI Artifacts | technique |
| mitre-atlas:AML.T0008 | Acquire Infrastructure | technique |
| mitre-atlas:AML.T0008.000 | AI Development Workspaces | technique |
| mitre-atlas:AML.T0008.001 | Consumer Hardware | technique |
| mitre-atlas:AML.T0008.002 | Domains | technique |
| mitre-atlas:AML.T0008.003 | Physical Countermeasures | technique |
| mitre-atlas:AML.T0008.004 | Serverless | technique |
| mitre-atlas:AML.T0008.005 | AI Service Proxies | technique |
| mitre-atlas:AML.T0010 | Supply Chain Compromise | technique |
| mitre-atlas:AML.T0010.000 | Hardware | technique |
| mitre-atlas:AML.T0010.001 | Software | technique |
| mitre-atlas:AML.T0010.002 | Data Repository | technique |
| mitre-atlas:AML.T0010.003 | Model Repository | technique |
| mitre-atlas:AML.T0010.004 | Container Registry | technique |
| mitre-atlas:AML.T0010.005 | AI Agent Tool | technique |
| mitre-atlas:AML.T0011 | User Execution | technique |
| mitre-atlas:AML.T0011.000 | Unsafe AI Artifacts | technique |
| mitre-atlas:AML.T0011.001 | Malicious Package | technique |
| mitre-atlas:AML.T0011.002 | Poisoned AI Agent Tool | technique |
| mitre-atlas:AML.T0011.003 | Malicious Link | technique |
| mitre-atlas:AML.T0012 | Valid Accounts | technique |
| mitre-atlas:AML.T0013 | Discover AI Model Ontology | technique |
| mitre-atlas:AML.T0014 | Discover AI Model Family | technique |
| mitre-atlas:AML.T0015 | Evade AI Model | technique |
| mitre-atlas:AML.T0016 | Obtain Capabilities | technique |
| mitre-atlas:AML.T0016.000 | Adversarial AI Attack Implementations | technique |
| mitre-atlas:AML.T0016.001 | Software Tools | technique |
| mitre-atlas:AML.T0016.002 | Generative AI | technique |
| mitre-atlas:AML.T0016.003 | Exploits | technique |
| mitre-atlas:AML.T0016.004 | AI Agent Tools | technique |
| mitre-atlas:AML.T0017 | Develop Capabilities | technique |
| mitre-atlas:AML.T0017.000 | Adversarial AI Attacks | technique |
| mitre-atlas:AML.T0017.001 | Autonomous Exploit Development | technique |
| mitre-atlas:AML.T0017.002 | AI Agent Tools | technique |
| mitre-atlas:AML.T0017.003 | Malware | technique |
| mitre-atlas:AML.T0018 | Manipulate AI Model | technique |
| mitre-atlas:AML.T0018.000 | Poison AI Model | technique |
| mitre-atlas:AML.T0018.001 | Modify AI Model Architecture | technique |
| mitre-atlas:AML.T0018.002 | Embed Malware | technique |
| mitre-atlas:AML.T0018.003 | Modify Prompt Construction Logic | technique |
| mitre-atlas:AML.T0020 | Training Data Poisoning | technique |
| mitre-atlas:AML.T0021 | Establish Accounts | technique |
| mitre-atlas:AML.T0024 | Exfiltration via AI Inference API | technique |
| mitre-atlas:AML.T0025 | Exfiltration via Cyber Means | technique |
| mitre-atlas:AML.T0029 | Denial of AI Service | technique |
| mitre-atlas:AML.T0031 | Erode AI Model Integrity | technique |
| mitre-atlas:AML.T0034 | Cost Harvesting | technique |
| mitre-atlas:AML.T0034.000 | Excessive Queries | technique |
| mitre-atlas:AML.T0034.001 | Resource-Intensive Queries | technique |
| mitre-atlas:AML.T0034.002 | Agentic Resource Consumption | technique |
| mitre-atlas:AML.T0035 | AI Artifact Collection | technique |
| mitre-atlas:AML.T0036 | Data from Information Repositories | technique |
| mitre-atlas:AML.T0037 | Data from Local System | technique |
| mitre-atlas:AML.T0040 | AI Model Inference API Access | technique |
| mitre-atlas:AML.T0041 | Physical Environment Access | technique |
| mitre-atlas:AML.T0042 | Verify Attack | technique |
| mitre-atlas:AML.T0043 | Craft Adversarial Data | technique |
| mitre-atlas:AML.T0043.000 | White-Box Optimization | technique |
| mitre-atlas:AML.T0043.001 | Black-Box Optimization | technique |
| mitre-atlas:AML.T0043.002 | Black-Box Transfer | technique |
| mitre-atlas:AML.T0043.003 | Manual Modification | technique |
| mitre-atlas:AML.T0043.004 | Insert Backdoor Trigger | technique |
| mitre-atlas:AML.T0044 | Full AI Model Access | technique |
| mitre-atlas:AML.T0046 | Spamming AI System with Chaff Data | technique |
| mitre-atlas:AML.T0047 | AI-Enabled Product or Service | technique |
| mitre-atlas:AML.T0048 | External Harms | technique |
| mitre-atlas:AML.T0048.000 | Financial Harm | technique |
| mitre-atlas:AML.T0048.001 | Reputational Harm | technique |
| mitre-atlas:AML.T0048.002 | Societal Harm | technique |
| mitre-atlas:AML.T0048.003 | User Harm | technique |
| mitre-atlas:AML.T0048.004 | AI Intellectual Property Theft | technique |
| mitre-atlas:AML.T0049 | Exploit Public-Facing Application | technique |
| mitre-atlas:AML.T0050 | Command and Scripting Interpreter | technique |
| mitre-atlas:AML.T0051 | LLM Prompt Injection | technique |
| mitre-atlas:AML.T0051.000 | Direct | technique |
| mitre-atlas:AML.T0051.001 | Indirect | technique |
| mitre-atlas:AML.T0051.002 | Triggered | technique |
| mitre-atlas:AML.T0052 | Phishing | technique |
| mitre-atlas:AML.T0052.000 | Spearphishing via Social Engineering LLM | technique |
| mitre-atlas:AML.T0052.001 | Deepfake-Assisted Phishing | technique |
| mitre-atlas:AML.T0053 | AI Agent Tool Invocation | technique |
| mitre-atlas:AML.T0054 | LLM Jailbreak | technique |
| mitre-atlas:AML.T0055 | Unsecured Credentials | technique |
| mitre-atlas:AML.T0059 | Erode Dataset Integrity | technique |
| mitre-atlas:AML.T0060 | Publish Hallucinated Entities | technique |
| mitre-atlas:AML.T0061 | LLM Prompt Self-Replication | technique |
| mitre-atlas:AML.T0062 | Discover LLM Hallucinations | technique |
| mitre-atlas:AML.T0063 | Discover AI Model Outputs | technique |
| mitre-atlas:AML.T0064 | Gather RAG-Indexed Targets | technique |
| mitre-atlas:AML.T0065 | LLM Prompt Crafting | technique |
| mitre-atlas:AML.T0066 | Retrieval Content Crafting | technique |
| mitre-atlas:AML.T0067 | LLM Trusted Output Components Manipulation | technique |
| mitre-atlas:AML.T0067.000 | Citations | technique |
| mitre-atlas:AML.T0068 | LLM Prompt Obfuscation | technique |
| mitre-atlas:AML.T0069 | Discover LLM System Information | technique |
| mitre-atlas:AML.T0069.000 | Special Character Sets | technique |
| mitre-atlas:AML.T0069.001 | System Instruction Keywords | technique |
| mitre-atlas:AML.T0069.002 | System Prompt | technique |
| mitre-atlas:AML.T0070 | RAG Poisoning | technique |
| mitre-atlas:AML.T0071 | False RAG Entry Injection | technique |
| mitre-atlas:AML.T0072 | Cyber Communication Channel | technique |
| mitre-atlas:AML.T0073 | Impersonation | technique |
| mitre-atlas:AML.T0074 | Masquerading | technique |
| mitre-atlas:AML.T0075 | Enterprise Resource Discovery | technique |
| mitre-atlas:AML.T0076 | Corrupt AI Model | technique |
| mitre-atlas:AML.T0077 | LLM Response Rendering | technique |
| mitre-atlas:AML.T0078 | Drive-by Compromise | technique |
| mitre-atlas:AML.T0079 | Stage Capabilities | technique |
| mitre-atlas:AML.T0080 | AI Agent Context Poisoning | technique |
| mitre-atlas:AML.T0080.000 | Memory | technique |
| mitre-atlas:AML.T0080.001 | Thread | technique |
| mitre-atlas:AML.T0081 | Modify AI Agent Configuration | technique |
| mitre-atlas:AML.T0082 | RAG Credential Harvesting | technique |
| mitre-atlas:AML.T0083 | Credentials from AI Agent Configuration | technique |
| mitre-atlas:AML.T0084 | Discover AI Agent Configuration | technique |
| mitre-atlas:AML.T0084.000 | Embedded Knowledge | technique |
| mitre-atlas:AML.T0084.001 | Tool Definitions | technique |
| mitre-atlas:AML.T0084.002 | Activation Triggers | technique |
| mitre-atlas:AML.T0084.003 | Call Chains | technique |
| mitre-atlas:AML.T0085 | Data from AI Services | technique |
| mitre-atlas:AML.T0085.000 | RAG Databases | technique |
| mitre-atlas:AML.T0085.001 | AI Agent Tools | technique |
| mitre-atlas:AML.T0085.002 | Conversation Context and Memory | technique |
| mitre-atlas:AML.T0085.003 | System Instructions | technique |
| mitre-atlas:AML.T0086 | Exfiltration via AI Agent Tool Invocation | technique |
| mitre-atlas:AML.T0087 | Gather Victim Identity Information | technique |
| mitre-atlas:AML.T0088 | Generate Deepfakes | technique |
| mitre-atlas:AML.T0089 | Enterprise Environment Discovery | technique |
| mitre-atlas:AML.T0090 | OS Credential Dumping | technique |
| mitre-atlas:AML.T0091 | Use Alternate Authentication Material | technique |
| mitre-atlas:AML.T0091.000 | Application Access Token | technique |
| mitre-atlas:AML.T0091.001 | Web Session Cookie | technique |
| mitre-atlas:AML.T0092 | Manipulate User LLM Chat History | technique |
| mitre-atlas:AML.T0093 | Prompt Infiltration via Public-Facing Application | technique |
| mitre-atlas:AML.T0094 | Delay Execution of LLM Instructions | technique |
| mitre-atlas:AML.T0095 | Search Open Websites/Domains | technique |
| mitre-atlas:AML.T0095.000 | Code Repositories | technique |
| mitre-atlas:AML.T0096 | AI Service API | technique |
| mitre-atlas:AML.T0097 | Virtualization/Sandbox Evasion | technique |
| mitre-atlas:AML.T0098 | AI Agent Tool Credential Harvesting | technique |
| mitre-atlas:AML.T0099 | AI Agent Tool Data Poisoning | technique |
| mitre-atlas:AML.T0100 | AI Agent Clickbait | technique |
| mitre-atlas:AML.T0101 | Data Destruction via AI Agent Tool Invocation | technique |
| mitre-atlas:AML.T0102 | Generate Malicious Commands | technique |
| mitre-atlas:AML.T0103 | Deploy AI Agent | technique |
| mitre-atlas:AML.T0105 | Escape to Host | technique |
| mitre-atlas:AML.T0106 | Exploitation for Credential Access | technique |
| mitre-atlas:AML.T0107 | Exploitation for Defense Evasion | technique |
| mitre-atlas:AML.T0108 | AI Agent | technique |
| mitre-atlas:AML.T0109 | AI Supply Chain Rug Pull | technique |
| mitre-atlas:AML.T0110 | AI Agent Tool Poisoning | technique |
| mitre-atlas:AML.T0110.000 | Definition and Instructions | technique |
| mitre-atlas:AML.T0110.001 | Implementation | technique |
| mitre-atlas:AML.T0110.002 | Runtime Response | technique |
| mitre-atlas:AML.T0111 | AI Supply Chain Reputation Inflation | technique |
| mitre-atlas:AML.T0112 | Machine Compromise | technique |
| mitre-atlas:AML.T0112.000 | Local AI Agent | technique |
| mitre-atlas:AML.T0112.001 | AI Artifacts | technique |
| mitre-atlas:AML.T0113 | Steal Web Session Cookie | technique |
| mitre-atlas:AML.T0114 | AI Service Web Interface | technique |
| mitre-atlas:AML.T0115 | Publish Poisoned AI Artifacts | technique |
| mitre-atlas:AML.T0115.000 | Datasets | technique |
| mitre-atlas:AML.T0115.001 | Models | technique |
| mitre-atlas:AML.T0115.002 | AI Agent Tools | technique |
| mitre-atlas:AML.T0116 | Autonomous Reconnaissance | technique |
| mitre-atlas:AML.T0117 | Autonomous Attack-Path Adaptation | technique |
| mitre-atlas:AML.T0118 | Autonomous AI Agent Communication | technique |
| mitre-atlas:AML.T0118.000 | Communication via Shared Artifacts | technique |
| mitre-atlas:AML.T0118.001 | Direct Agent Communication | technique |
| mitre-atlas:AML.T0119 | Exploit Automated Artifact Processing Pipeline | technique |
| mitre-atlas:AML.T0120 | AI Artifact Repository | technique |
| mitre-atlas:AML.T0121 | AI Agent Environment Reconstruction | technique |
| mitre-atlas:AML.T0122 | Exploitation of Remote Services | technique |
| mitre-atlas:AML.T0123 | Obfuscated Files or Information | technique |
| mitre-atlas:AML.T0124 | Autonomous Attack Orchestration | technique |
| mitre-atlas:AML.T0125 | Create Account | technique |
| mitre-atlas:AML.T0126 | Automated Collection | technique |
| mitre-atlas:AML.T0127 | Data Staged | technique |
| mitre-atlas:AML.T0128 | Compromise Infrastructure | technique |
| mitre-atlas:AML.T0129 | Triggers in Multimodal Inputs | technique |
| mitre-atlas:AML.T0130 | AI Agent Response Biasing | technique |
| mitre-atlas:AML.T0131 | Crafted AI Assistant Links | technique |
| mitre-atlas:AML.T0132 | Misconfigured or Publicly Exposed AI Services | technique |
| mitre-atlas:AML.T0133 | Discover AI Agent Runtime Capabilities | technique |
| mitre-atlas:AML.T0134 | AI Targeted Cloaking | technique |
| mitre-atlas:AML.T0135 | Outputs from AI Models | technique |
| mitre-atlas:AML.T0136 | Exfiltration via AI User Interface | technique |
| mitre-atlas:AML.T0137 | Training Data Information from AI Models | technique |
| mitre-atlas:AML.T0137.000 | Infer Membership | technique |
| mitre-atlas:AML.T0137.001 | Infer Properties | technique |
| mitre-atlas:AML.T0137.002 | Invert AI Model | technique |
| mitre-atlas:AML.T0137.003 | Extract Memorized Data | technique |
| mitre-atlas:AML.T0138 | Indicator Removal | technique |
| mitre-atlas:AML.T0139 | Compromise Accounts | technique |
| mitre-atlas:AML.T0140 | Centralized AI Service Request Routing | technique |
| mitre-atlas:AML.T0141 | AI Service Request Metadata Sanitization | technique |
| mitre-atlas:AML.T0142 | Event Triggered Execution | technique |
| mitre-atlas:AML.T0143 | LLM Prompt Propagation | technique |
| mitre-atlas:AML.T0144 | Recover AI Model Internals | technique |
| mitre-atlas:AML.T0145 | Poison AI Agent Learning Environment | technique |
| mitre-atlas:AML.TA0000 | AI Model Access | tactic |
| mitre-atlas:AML.TA0001 | AI Attack Adaptation | tactic |
| mitre-atlas:AML.TA0002 | Reconnaissance | tactic |
| mitre-atlas:AML.TA0003 | Resource Development | tactic |
| mitre-atlas:AML.TA0004 | Initial Access | tactic |
| mitre-atlas:AML.TA0005 | Execution | tactic |
| mitre-atlas:AML.TA0006 | Persistence | tactic |
| mitre-atlas:AML.TA0007 | Defense Evasion | tactic |
| mitre-atlas:AML.TA0008 | Discovery | tactic |
| mitre-atlas:AML.TA0009 | Collection | tactic |
| mitre-atlas:AML.TA0010 | Exfiltration | tactic |
| mitre-atlas:AML.TA0011 | Impact | tactic |
| mitre-atlas:AML.TA0012 | Privilege Escalation | tactic |
| mitre-atlas:AML.TA0013 | Credential Access | tactic |
| mitre-atlas:AML.TA0014 | Command and Control | tactic |
| mitre-atlas:AML.TA0015 | Lateral Movement | tactic |

## NIST SP 800-171

| ID | Name | Kind |
| --- | --- | --- |
| nist-800-171:03.01 | Access Control | family |
| nist-800-171:03.01.01 | Account Management | requirement |
| nist-800-171:03.01.02 | Access Enforcement | requirement |
| nist-800-171:03.01.03 | Information Flow Enforcement | requirement |
| nist-800-171:03.01.04 | Separation of Duties | requirement |
| nist-800-171:03.01.05 | Least Privilege | requirement |
| nist-800-171:03.01.06 | Least Privilege – Privileged Accounts | requirement |
| nist-800-171:03.01.07 | Least Privilege – Privileged Functions | requirement |
| nist-800-171:03.01.08 | Unsuccessful Logon Attempts | requirement |
| nist-800-171:03.01.09 | System Use Notification | requirement |
| nist-800-171:03.01.10 | Device Lock | requirement |
| nist-800-171:03.01.11 | Session Termination | requirement |
| nist-800-171:03.01.12 | Remote Access | requirement |
| nist-800-171:03.01.13 | 03.01.13 | requirement (deprecated) |
| nist-800-171:03.01.14 | 03.01.14 | requirement (deprecated) |
| nist-800-171:03.01.15 | 03.01.15 | requirement (deprecated) |
| nist-800-171:03.01.16 | Wireless Access | requirement |
| nist-800-171:03.01.17 | 03.01.17 | requirement (deprecated) |
| nist-800-171:03.01.18 | Access Control for Mobile Devices | requirement |
| nist-800-171:03.01.19 | 03.01.19 | requirement (deprecated) |
| nist-800-171:03.01.20 | Use of External Systems | requirement |
| nist-800-171:03.01.21 | 03.01.21 | requirement (deprecated) |
| nist-800-171:03.01.22 | Publicly Accessible Content | requirement |
| nist-800-171:03.02 | Awareness and Training | family |
| nist-800-171:03.02.01 | Literacy Training and Awareness | requirement |
| nist-800-171:03.02.02 | Role-Based Training | requirement |
| nist-800-171:03.02.03 | 03.02.03 | requirement (deprecated) |
| nist-800-171:03.03 | Audit and Accountability | family |
| nist-800-171:03.03.01 | Event Logging | requirement |
| nist-800-171:03.03.02 | Audit Record Content | requirement |
| nist-800-171:03.03.03 | Audit Record Generation | requirement |
| nist-800-171:03.03.04 | Response to Audit Logging Process Failures | requirement |
| nist-800-171:03.03.05 | Audit Record Review, Analysis, and Reporting | requirement |
| nist-800-171:03.03.06 | Audit Record Reduction and Report Generation | requirement |
| nist-800-171:03.03.07 | Time Stamps | requirement |
| nist-800-171:03.03.08 | Protection of Audit Information | requirement |
| nist-800-171:03.03.09 | 03.03.09 | requirement (deprecated) |
| nist-800-171:03.04 | Configuration Management | family |
| nist-800-171:03.04.01 | Baseline Configuration | requirement |
| nist-800-171:03.04.02 | Configuration Settings | requirement |
| nist-800-171:03.04.03 | Configuration Change Control | requirement |
| nist-800-171:03.04.04 | Impact Analyses | requirement |
| nist-800-171:03.04.05 | Access Restrictions for Change | requirement |
| nist-800-171:03.04.06 | Least Functionality | requirement |
| nist-800-171:03.04.07 | 03.04.07 | requirement (deprecated) |
| nist-800-171:03.04.08 | Authorized Software – Allow by Exception | requirement |
| nist-800-171:03.04.09 | 03.04.09 | requirement (deprecated) |
| nist-800-171:03.04.10 | System Component Inventory | requirement |
| nist-800-171:03.04.11 | Information Location | requirement |
| nist-800-171:03.04.12 | System and Component Configuration for High-Risk Areas | requirement |
| nist-800-171:03.05 | Identification and Authentication | family |
| nist-800-171:03.05.01 | User Identification and Authentication | requirement |
| nist-800-171:03.05.02 | Device Identification and Authentication | requirement |
| nist-800-171:03.05.03 | Multi-Factor Authentication | requirement |
| nist-800-171:03.05.04 | Replay-Resistant Authentication | requirement |
| nist-800-171:03.05.05 | Identifier Management | requirement |
| nist-800-171:03.05.06 | 03.05.06 | requirement (deprecated) |
| nist-800-171:03.05.07 | Password Management | requirement |
| nist-800-171:03.05.08 | 03.05.08 | requirement (deprecated) |
| nist-800-171:03.05.09 | 03.05.09 | requirement (deprecated) |
| nist-800-171:03.05.10 | 03.05.10 | requirement (deprecated) |
| nist-800-171:03.05.11 | Authentication Feedback | requirement |
| nist-800-171:03.05.12 | Authenticator Management | requirement |
| nist-800-171:03.06 | Incident Response | family |
| nist-800-171:03.06.01 | Incident Handling | requirement |
| nist-800-171:03.06.02 | Incident Monitoring, Reporting, and Response Assistance | requirement |
| nist-800-171:03.06.03 | Incident Response Testing | requirement |
| nist-800-171:03.06.04 | Incident Response Training | requirement |
| nist-800-171:03.06.05 | Incident Response Plan | requirement |
| nist-800-171:03.07 | Maintenance | family |
| nist-800-171:03.07.01 | 03.07.01 | requirement (deprecated) |
| nist-800-171:03.07.02 | 03.07.02 | requirement (deprecated) |
| nist-800-171:03.07.03 | 03.07.03 | requirement (deprecated) |
| nist-800-171:03.07.04 | Maintenance Tools | requirement |
| nist-800-171:03.07.05 | Nonlocal Maintenance | requirement |
| nist-800-171:03.07.06 | Maintenance Personnel | requirement |
| nist-800-171:03.08 | Media Protection | family |
| nist-800-171:03.08.01 | Media Storage | requirement |
| nist-800-171:03.08.02 | Media Access | requirement |
| nist-800-171:03.08.03 | Media Sanitization | requirement |
| nist-800-171:03.08.04 | Media Marking | requirement |
| nist-800-171:03.08.05 | Media Transport | requirement |
| nist-800-171:03.08.06 | 03.08.06 | requirement (deprecated) |
| nist-800-171:03.08.07 | Media Use | requirement |
| nist-800-171:03.08.08 | 03.08.08 | requirement (deprecated) |
| nist-800-171:03.08.09 | System Backup – Cryptographic Protection | requirement |
| nist-800-171:03.09 | Personnel Security | family |
| nist-800-171:03.09.01 | Personnel Screening | requirement |
| nist-800-171:03.09.02 | Personnel Termination and Transfer | requirement |
| nist-800-171:03.10 | Physical Protection | family |
| nist-800-171:03.10.01 | Physical Access Authorizations | requirement |
| nist-800-171:03.10.02 | Monitoring Physical Access | requirement |
| nist-800-171:03.10.03 | 03.10.03 | requirement (deprecated) |
| nist-800-171:03.10.04 | 03.10.04 | requirement (deprecated) |
| nist-800-171:03.10.05 | 03.10.05 | requirement (deprecated) |
| nist-800-171:03.10.06 | Alternate Work Site | requirement |
| nist-800-171:03.10.07 | Physical Access Control | requirement |
| nist-800-171:03.10.08 | Access Control for Transmission | requirement |
| nist-800-171:03.11 | Risk Assessment | family |
| nist-800-171:03.11.01 | Risk Assessment | requirement |
| nist-800-171:03.11.02 | Vulnerability Monitoring and Scanning | requirement |
| nist-800-171:03.11.03 | 03.11.03 | requirement (deprecated) |
| nist-800-171:03.11.04 | Risk Response | requirement |
| nist-800-171:03.12 | Security Assessment and Monitoring | family |
| nist-800-171:03.12.01 | Security Assessment | requirement |
| nist-800-171:03.12.02 | Plan of Action and Milestones | requirement |
| nist-800-171:03.12.03 | Continuous Monitoring | requirement |
| nist-800-171:03.12.04 | 03.12.04 | requirement (deprecated) |
| nist-800-171:03.12.05 | Information Exchange | requirement |
| nist-800-171:03.13 | System and Communications Protection | family |
| nist-800-171:03.13.01 | Boundary Protection | requirement |
| nist-800-171:03.13.02 | 03.13.02 | requirement (deprecated) |
| nist-800-171:03.13.03 | 03.13.03 | requirement (deprecated) |
| nist-800-171:03.13.04 | Information in Shared System Resources | requirement |
| nist-800-171:03.13.05 | 03.13.05 | requirement (deprecated) |
| nist-800-171:03.13.06 | Network Communications – Deny by Default – Allow by Exception | requirement |
| nist-800-171:03.13.07 | 03.13.07 | requirement (deprecated) |
| nist-800-171:03.13.08 | Transmission and Storage Confidentiality | requirement |
| nist-800-171:03.13.09 | Network Disconnect | requirement |
| nist-800-171:03.13.10 | Cryptographic Key Establishment and Management | requirement |
| nist-800-171:03.13.11 | Cryptographic Protection | requirement |
| nist-800-171:03.13.12 | Collaborative Computing Devices and Applications | requirement |
| nist-800-171:03.13.13 | Mobile Code | requirement |
| nist-800-171:03.13.14 | 03.13.14 | requirement (deprecated) |
| nist-800-171:03.13.15 | Session Authenticity | requirement |
| nist-800-171:03.13.16 | 03.13.16 | requirement (deprecated) |
| nist-800-171:03.14 | System and Information Integrity | family |
| nist-800-171:03.14.01 | Flaw Remediation | requirement |
| nist-800-171:03.14.02 | Malicious Code Protection | requirement |
| nist-800-171:03.14.03 | Security Alerts, Advisories, and Directives | requirement |
| nist-800-171:03.14.04 | 03.14.04 | requirement (deprecated) |
| nist-800-171:03.14.05 | 03.14.05 | requirement (deprecated) |
| nist-800-171:03.14.06 | System Monitoring | requirement |
| nist-800-171:03.14.07 | 03.14.07 | requirement (deprecated) |
| nist-800-171:03.14.08 | Information Management and Retention | requirement |
| nist-800-171:03.15 | Planning | family |
| nist-800-171:03.15.01 | Policy and Procedures | requirement |
| nist-800-171:03.15.02 | System Security Plan | requirement |
| nist-800-171:03.15.03 | Rules of Behavior | requirement |
| nist-800-171:03.16 | System and Services Acquisition | family |
| nist-800-171:03.16.01 | Security Engineering Principles | requirement |
| nist-800-171:03.16.02 | Unsupported System Components | requirement |
| nist-800-171:03.16.03 | External System Services | requirement |
| nist-800-171:03.17 | Supply Chain Risk Management | family |
| nist-800-171:03.17.01 | Supply Chain Risk Management Plan | requirement |
| nist-800-171:03.17.02 | Acquisition Strategies, Tools, and Methods | requirement |
| nist-800-171:03.17.03 | Supply Chain Requirements and Processes | requirement |

## NIST SP 800-53

| ID | Name | Kind |
| --- | --- | --- |
| nist-800-53:AC | Access Control | family |
| nist-800-53:AC-1 | Policy and Procedures | SP800-53 |
| nist-800-53:AC-10 | Concurrent Session Control | SP800-53 |
| nist-800-53:AC-11 | Device Lock | SP800-53 |
| nist-800-53:AC-11(1) | Pattern-hiding Displays | SP800-53-enhancement |
| nist-800-53:AC-12 | Session Termination | SP800-53 |
| nist-800-53:AC-12(1) | User-initiated Logouts | SP800-53-enhancement |
| nist-800-53:AC-12(2) | Termination Message | SP800-53-enhancement |
| nist-800-53:AC-12(3) | Timeout Warning Message | SP800-53-enhancement |
| nist-800-53:AC-13 | Supervision and Review — Access Control | SP800-53 (deprecated) |
| nist-800-53:AC-14 | Permitted Actions Without Identification or Authentication | SP800-53 |
| nist-800-53:AC-14(1) | Necessary Uses | SP800-53-enhancement (deprecated) |
| nist-800-53:AC-15 | Automated Marking | SP800-53 (deprecated) |
| nist-800-53:AC-16 | Security and Privacy Attributes | SP800-53 |
| nist-800-53:AC-16(1) | Dynamic Attribute Association | SP800-53-enhancement |
| nist-800-53:AC-16(10) | Attribute Configuration by Authorized Individuals | SP800-53-enhancement |
| nist-800-53:AC-16(2) | Attribute Value Changes by Authorized Individuals | SP800-53-enhancement |
| nist-800-53:AC-16(3) | Maintenance of Attribute Associations by System | SP800-53-enhancement |
| nist-800-53:AC-16(4) | Association of Attributes by Authorized Individuals | SP800-53-enhancement |
| nist-800-53:AC-16(5) | Attribute Displays on Objects to Be Output | SP800-53-enhancement |
| nist-800-53:AC-16(6) | Maintenance of Attribute Association | SP800-53-enhancement |
| nist-800-53:AC-16(7) | Consistent Attribute Interpretation | SP800-53-enhancement |
| nist-800-53:AC-16(8) | Association Techniques and Technologies | SP800-53-enhancement |
| nist-800-53:AC-16(9) | Attribute Reassignment — Regrading Mechanisms | SP800-53-enhancement |
| nist-800-53:AC-17 | Remote Access | SP800-53 |
| nist-800-53:AC-17(1) | Monitoring and Control | SP800-53-enhancement |
| nist-800-53:AC-17(10) | Authenticate Remote Commands | SP800-53-enhancement |
| nist-800-53:AC-17(2) | Protection of Confidentiality and Integrity Using Encryption | SP800-53-enhancement |
| nist-800-53:AC-17(3) | Managed Access Control Points | SP800-53-enhancement |
| nist-800-53:AC-17(4) | Privileged Commands and Access | SP800-53-enhancement |
| nist-800-53:AC-17(5) | Monitoring for Unauthorized Connections | SP800-53-enhancement (deprecated) |
| nist-800-53:AC-17(6) | Protection of Mechanism Information | SP800-53-enhancement |
| nist-800-53:AC-17(7) | Additional Protection for Security Function Access | SP800-53-enhancement (deprecated) |
| nist-800-53:AC-17(8) | Disable Nonsecure Network Protocols | SP800-53-enhancement (deprecated) |
| nist-800-53:AC-17(9) | Disconnect or Disable Access | SP800-53-enhancement |
| nist-800-53:AC-18 | Wireless Access | SP800-53 |
| nist-800-53:AC-18(1) | Authentication and Encryption | SP800-53-enhancement |
| nist-800-53:AC-18(2) | Monitoring Unauthorized Connections | SP800-53-enhancement (deprecated) |
| nist-800-53:AC-18(3) | Disable Wireless Networking | SP800-53-enhancement |
| nist-800-53:AC-18(4) | Restrict Configurations by Users | SP800-53-enhancement |
| nist-800-53:AC-18(5) | Antennas and Transmission Power Levels | SP800-53-enhancement |
| nist-800-53:AC-19 | Access Control for Mobile Devices | SP800-53 |
| nist-800-53:AC-19(1) | Use of Writable and Portable Storage Devices | SP800-53-enhancement (deprecated) |
| nist-800-53:AC-19(2) | Use of Personally Owned Portable Storage Devices | SP800-53-enhancement (deprecated) |
| nist-800-53:AC-19(3) | Use of Portable Storage Devices with No Identifiable Owner | SP800-53-enhancement (deprecated) |
| nist-800-53:AC-19(4) | Restrictions for Classified Information | SP800-53-enhancement |
| nist-800-53:AC-19(5) | Full Device or Container-based Encryption | SP800-53-enhancement |
| nist-800-53:AC-2 | Account Management | SP800-53 |
| nist-800-53:AC-2(1) | Automated System Account Management | SP800-53-enhancement |
| nist-800-53:AC-2(10) | Shared and Group Account Credential Change | SP800-53-enhancement (deprecated) |
| nist-800-53:AC-2(11) | Usage Conditions | SP800-53-enhancement |
| nist-800-53:AC-2(12) | Account Monitoring for Atypical Usage | SP800-53-enhancement |
| nist-800-53:AC-2(13) | Disable Accounts for High-risk Individuals | SP800-53-enhancement |
| nist-800-53:AC-2(2) | Automated Temporary and Emergency Account Management | SP800-53-enhancement |
| nist-800-53:AC-2(3) | Disable Accounts | SP800-53-enhancement |
| nist-800-53:AC-2(4) | Automated Audit Actions | SP800-53-enhancement |
| nist-800-53:AC-2(5) | Inactivity Logout | SP800-53-enhancement |
| nist-800-53:AC-2(6) | Dynamic Privilege Management | SP800-53-enhancement |
| nist-800-53:AC-2(7) | Privileged User Accounts | SP800-53-enhancement |
| nist-800-53:AC-2(8) | Dynamic Account Management | SP800-53-enhancement |
| nist-800-53:AC-2(9) | Restrictions on Use of Shared and Group Accounts | SP800-53-enhancement |
| nist-800-53:AC-20 | Use of External Systems | SP800-53 |
| nist-800-53:AC-20(1) | Limits on Authorized Use | SP800-53-enhancement |
| nist-800-53:AC-20(2) | Portable Storage Devices — Restricted Use | SP800-53-enhancement |
| nist-800-53:AC-20(3) | Non-organizationally Owned Systems — Restricted Use | SP800-53-enhancement |
| nist-800-53:AC-20(4) | Network Accessible Storage Devices — Prohibited Use | SP800-53-enhancement |
| nist-800-53:AC-20(5) | Portable Storage Devices — Prohibited Use | SP800-53-enhancement |
| nist-800-53:AC-21 | Information Sharing | SP800-53 |
| nist-800-53:AC-21(1) | Automated Decision Support | SP800-53-enhancement |
| nist-800-53:AC-21(2) | Information Search and Retrieval | SP800-53-enhancement |
| nist-800-53:AC-22 | Publicly Accessible Content | SP800-53 |
| nist-800-53:AC-23 | Data Mining Protection | SP800-53 |
| nist-800-53:AC-24 | Access Control Decisions | SP800-53 |
| nist-800-53:AC-24(1) | Transmit Access Authorization Information | SP800-53-enhancement |
| nist-800-53:AC-24(2) | No User or Process Identity | SP800-53-enhancement |
| nist-800-53:AC-25 | Reference Monitor | SP800-53 |
| nist-800-53:AC-3 | Access Enforcement | SP800-53 |
| nist-800-53:AC-3(1) | Restricted Access to Privileged Functions | SP800-53-enhancement (deprecated) |
| nist-800-53:AC-3(10) | Audited Override of Access Control Mechanisms | SP800-53-enhancement |
| nist-800-53:AC-3(11) | Restrict Access to Specific Information Types | SP800-53-enhancement |
| nist-800-53:AC-3(12) | Assert and Enforce Application Access | SP800-53-enhancement |
| nist-800-53:AC-3(13) | Attribute-based Access Control | SP800-53-enhancement |
| nist-800-53:AC-3(14) | Individual Access | SP800-53-enhancement |
| nist-800-53:AC-3(15) | Discretionary and Mandatory Access Control | SP800-53-enhancement |
| nist-800-53:AC-3(2) | Dual Authorization | SP800-53-enhancement |
| nist-800-53:AC-3(3) | Mandatory Access Control | SP800-53-enhancement |
| nist-800-53:AC-3(4) | Discretionary Access Control | SP800-53-enhancement |
| nist-800-53:AC-3(5) | Security-relevant Information | SP800-53-enhancement |
| nist-800-53:AC-3(6) | Protection of User and System Information | SP800-53-enhancement (deprecated) |
| nist-800-53:AC-3(7) | Role-based Access Control | SP800-53-enhancement |
| nist-800-53:AC-3(8) | Revocation of Access Authorizations | SP800-53-enhancement |
| nist-800-53:AC-3(9) | Controlled Release | SP800-53-enhancement |
| nist-800-53:AC-4 | Information Flow Enforcement | SP800-53 |
| nist-800-53:AC-4(1) | Object Security and Privacy Attributes | SP800-53-enhancement |
| nist-800-53:AC-4(10) | Enable and Disable Security or Privacy Policy Filters | SP800-53-enhancement |
| nist-800-53:AC-4(11) | Configuration of Security or Privacy Policy Filters | SP800-53-enhancement |
| nist-800-53:AC-4(12) | Data Type Identifiers | SP800-53-enhancement |
| nist-800-53:AC-4(13) | Decomposition into Policy-relevant Subcomponents | SP800-53-enhancement |
| nist-800-53:AC-4(14) | Security or Privacy Policy Filter Constraints | SP800-53-enhancement |
| nist-800-53:AC-4(15) | Detection of Unsanctioned Information | SP800-53-enhancement |
| nist-800-53:AC-4(16) | Information Transfers on Interconnected Systems | SP800-53-enhancement (deprecated) |
| nist-800-53:AC-4(17) | Domain Authentication | SP800-53-enhancement |
| nist-800-53:AC-4(18) | Security Attribute Binding | SP800-53-enhancement (deprecated) |
| nist-800-53:AC-4(19) | Validation of Metadata | SP800-53-enhancement |
| nist-800-53:AC-4(2) | Processing Domains | SP800-53-enhancement |
| nist-800-53:AC-4(20) | Approved Solutions | SP800-53-enhancement |
| nist-800-53:AC-4(21) | Physical or Logical Separation of Information Flows | SP800-53-enhancement |
| nist-800-53:AC-4(22) | Access Only | SP800-53-enhancement |
| nist-800-53:AC-4(23) | Modify Non-releasable Information | SP800-53-enhancement |
| nist-800-53:AC-4(24) | Internal Normalized Format | SP800-53-enhancement |
| nist-800-53:AC-4(25) | Data Sanitization | SP800-53-enhancement |
| nist-800-53:AC-4(26) | Audit Filtering Actions | SP800-53-enhancement |
| nist-800-53:AC-4(27) | Redundant/Independent Filtering Mechanisms | SP800-53-enhancement |
| nist-800-53:AC-4(28) | Linear Filter Pipelines | SP800-53-enhancement |
| nist-800-53:AC-4(29) | Filter Orchestration Engines | SP800-53-enhancement |
| nist-800-53:AC-4(3) | Dynamic Information Flow Control | SP800-53-enhancement |
| nist-800-53:AC-4(30) | Filter Mechanisms Using Multiple Processes | SP800-53-enhancement |
| nist-800-53:AC-4(31) | Failed Content Transfer Prevention | SP800-53-enhancement |
| nist-800-53:AC-4(32) | Process Requirements for Information Transfer | SP800-53-enhancement |
| nist-800-53:AC-4(4) | Flow Control of Encrypted Information | SP800-53-enhancement |
| nist-800-53:AC-4(5) | Embedded Data Types | SP800-53-enhancement |
| nist-800-53:AC-4(6) | Metadata | SP800-53-enhancement |
| nist-800-53:AC-4(7) | One-way Flow Mechanisms | SP800-53-enhancement |
| nist-800-53:AC-4(8) | Security and Privacy Policy Filters | SP800-53-enhancement |
| nist-800-53:AC-4(9) | Human Reviews | SP800-53-enhancement |
| nist-800-53:AC-5 | Separation of Duties | SP800-53 |
| nist-800-53:AC-6 | Least Privilege | SP800-53 |
| nist-800-53:AC-6(1) | Authorize Access to Security Functions | SP800-53-enhancement |
| nist-800-53:AC-6(10) | Prohibit Non-privileged Users from Executing Privileged Functions | SP800-53-enhancement |
| nist-800-53:AC-6(2) | Non-privileged Access for Nonsecurity Functions | SP800-53-enhancement |
| nist-800-53:AC-6(3) | Network Access to Privileged Commands | SP800-53-enhancement |
| nist-800-53:AC-6(4) | Separate Processing Domains | SP800-53-enhancement |
| nist-800-53:AC-6(5) | Privileged Accounts | SP800-53-enhancement |
| nist-800-53:AC-6(6) | Privileged Access by Non-organizational Users | SP800-53-enhancement |
| nist-800-53:AC-6(7) | Review of User Privileges | SP800-53-enhancement |
| nist-800-53:AC-6(8) | Privilege Levels for Code Execution | SP800-53-enhancement |
| nist-800-53:AC-6(9) | Log Use of Privileged Functions | SP800-53-enhancement |
| nist-800-53:AC-7 | Unsuccessful Logon Attempts | SP800-53 |
| nist-800-53:AC-7(1) | Automatic Account Lock | SP800-53-enhancement (deprecated) |
| nist-800-53:AC-7(2) | Purge or Wipe Mobile Device | SP800-53-enhancement |
| nist-800-53:AC-7(3) | Biometric Attempt Limiting | SP800-53-enhancement |
| nist-800-53:AC-7(4) | Use of Alternate Authentication Factor | SP800-53-enhancement |
| nist-800-53:AC-8 | System Use Notification | SP800-53 |
| nist-800-53:AC-9 | Previous Logon Notification | SP800-53 |
| nist-800-53:AC-9(1) | Unsuccessful Logons | SP800-53-enhancement |
| nist-800-53:AC-9(2) | Successful and Unsuccessful Logons | SP800-53-enhancement |
| nist-800-53:AC-9(3) | Notification of Account Changes | SP800-53-enhancement |
| nist-800-53:AC-9(4) | Additional Logon Information | SP800-53-enhancement |
| nist-800-53:AT | Awareness and Training | family |
| nist-800-53:AT-1 | Policy and Procedures | SP800-53 |
| nist-800-53:AT-2 | Literacy Training and Awareness | SP800-53 |
| nist-800-53:AT-2(1) | Practical Exercises | SP800-53-enhancement |
| nist-800-53:AT-2(2) | Insider Threat | SP800-53-enhancement |
| nist-800-53:AT-2(3) | Social Engineering and Mining | SP800-53-enhancement |
| nist-800-53:AT-2(4) | Suspicious Communications and Anomalous System Behavior | SP800-53-enhancement |
| nist-800-53:AT-2(5) | Advanced Persistent Threat | SP800-53-enhancement |
| nist-800-53:AT-2(6) | Cyber Threat Environment | SP800-53-enhancement |
| nist-800-53:AT-3 | Role-based Training | SP800-53 |
| nist-800-53:AT-3(1) | Environmental Controls | SP800-53-enhancement |
| nist-800-53:AT-3(2) | Physical Security Controls | SP800-53-enhancement |
| nist-800-53:AT-3(3) | Practical Exercises | SP800-53-enhancement |
| nist-800-53:AT-3(4) | Suspicious Communications and Anomalous System Behavior | SP800-53-enhancement (deprecated) |
| nist-800-53:AT-3(5) | Processing Personally Identifiable Information | SP800-53-enhancement |
| nist-800-53:AT-4 | Training Records | SP800-53 |
| nist-800-53:AT-5 | Contacts with Security Groups and Associations | SP800-53 (deprecated) |
| nist-800-53:AT-6 | Training Feedback | SP800-53 |
| nist-800-53:AU | Audit and Accountability | family |
| nist-800-53:AU-1 | Policy and Procedures | SP800-53 |
| nist-800-53:AU-10 | Non-repudiation | SP800-53 |
| nist-800-53:AU-10(1) | Association of Identities | SP800-53-enhancement |
| nist-800-53:AU-10(2) | Validate Binding of Information Producer Identity | SP800-53-enhancement |
| nist-800-53:AU-10(3) | Chain of Custody | SP800-53-enhancement |
| nist-800-53:AU-10(4) | Validate Binding of Information Reviewer Identity | SP800-53-enhancement |
| nist-800-53:AU-10(5) | Digital Signatures | SP800-53-enhancement (deprecated) |
| nist-800-53:AU-11 | Audit Record Retention | SP800-53 |
| nist-800-53:AU-11(1) | Long-term Retrieval Capability | SP800-53-enhancement |
| nist-800-53:AU-12 | Audit Record Generation | SP800-53 |
| nist-800-53:AU-12(1) | System-wide and Time-correlated Audit Trail | SP800-53-enhancement |
| nist-800-53:AU-12(2) | Standardized Formats | SP800-53-enhancement |
| nist-800-53:AU-12(3) | Changes by Authorized Individuals | SP800-53-enhancement |
| nist-800-53:AU-12(4) | Query Parameter Audits of Personally Identifiable Information | SP800-53-enhancement |
| nist-800-53:AU-13 | Monitoring for Information Disclosure | SP800-53 |
| nist-800-53:AU-13(1) | Use of Automated Tools | SP800-53-enhancement |
| nist-800-53:AU-13(2) | Review of Monitored Sites | SP800-53-enhancement |
| nist-800-53:AU-13(3) | Unauthorized Replication of Information | SP800-53-enhancement |
| nist-800-53:AU-14 | Session Audit | SP800-53 |
| nist-800-53:AU-14(1) | System Start-up | SP800-53-enhancement |
| nist-800-53:AU-14(2) | Capture and Record Content | SP800-53-enhancement (deprecated) |
| nist-800-53:AU-14(3) | Remote Viewing and Listening | SP800-53-enhancement |
| nist-800-53:AU-15 | Alternate Audit Logging Capability | SP800-53 (deprecated) |
| nist-800-53:AU-16 | Cross-organizational Audit Logging | SP800-53 |
| nist-800-53:AU-16(1) | Identity Preservation | SP800-53-enhancement |
| nist-800-53:AU-16(2) | Sharing of Audit Information | SP800-53-enhancement |
| nist-800-53:AU-16(3) | Disassociability | SP800-53-enhancement |
| nist-800-53:AU-2 | Event Logging | SP800-53 |
| nist-800-53:AU-2(1) | Compilation of Audit Records from Multiple Sources | SP800-53-enhancement (deprecated) |
| nist-800-53:AU-2(2) | Selection of Audit Events by Component | SP800-53-enhancement (deprecated) |
| nist-800-53:AU-2(3) | Reviews and Updates | SP800-53-enhancement (deprecated) |
| nist-800-53:AU-2(4) | Privileged Functions | SP800-53-enhancement (deprecated) |
| nist-800-53:AU-3 | Content of Audit Records | SP800-53 |
| nist-800-53:AU-3(1) | Additional Audit Information | SP800-53-enhancement |
| nist-800-53:AU-3(2) | Centralized Management of Planned Audit Record Content | SP800-53-enhancement (deprecated) |
| nist-800-53:AU-3(3) | Limit Personally Identifiable Information Elements | SP800-53-enhancement |
| nist-800-53:AU-4 | Audit Log Storage Capacity | SP800-53 |
| nist-800-53:AU-4(1) | Transfer to Alternate Storage | SP800-53-enhancement |
| nist-800-53:AU-5 | Response to Audit Logging Process Failures | SP800-53 |
| nist-800-53:AU-5(1) | Storage Capacity Warning | SP800-53-enhancement |
| nist-800-53:AU-5(2) | Real-time Alerts | SP800-53-enhancement |
| nist-800-53:AU-5(3) | Configurable Traffic Volume Thresholds | SP800-53-enhancement |
| nist-800-53:AU-5(4) | Shutdown on Failure | SP800-53-enhancement |
| nist-800-53:AU-5(5) | Alternate Audit Logging Capability | SP800-53-enhancement |
| nist-800-53:AU-6 | Audit Record Review, Analysis, and Reporting | SP800-53 |
| nist-800-53:AU-6(1) | Automated Process Integration | SP800-53-enhancement |
| nist-800-53:AU-6(10) | Audit Level Adjustment | SP800-53-enhancement (deprecated) |
| nist-800-53:AU-6(2) | Automated Security Alerts | SP800-53-enhancement (deprecated) |
| nist-800-53:AU-6(3) | Correlate Audit Record Repositories | SP800-53-enhancement |
| nist-800-53:AU-6(4) | Central Review and Analysis | SP800-53-enhancement |
| nist-800-53:AU-6(5) | Integrated Analysis of Audit Records | SP800-53-enhancement |
| nist-800-53:AU-6(6) | Correlation with Physical Monitoring | SP800-53-enhancement |
| nist-800-53:AU-6(7) | Permitted Actions | SP800-53-enhancement |
| nist-800-53:AU-6(8) | Full Text Analysis of Privileged Commands | SP800-53-enhancement |
| nist-800-53:AU-6(9) | Correlation with Information from Nontechnical Sources | SP800-53-enhancement |
| nist-800-53:AU-7 | Audit Record Reduction and Report Generation | SP800-53 |
| nist-800-53:AU-7(1) | Automatic Processing | SP800-53-enhancement |
| nist-800-53:AU-7(2) | Automatic Sort and Search | SP800-53-enhancement (deprecated) |
| nist-800-53:AU-8 | Time Stamps | SP800-53 |
| nist-800-53:AU-8(1) | Synchronization with Authoritative Time Source | SP800-53-enhancement (deprecated) |
| nist-800-53:AU-8(2) | Secondary Authoritative Time Source | SP800-53-enhancement (deprecated) |
| nist-800-53:AU-9 | Protection of Audit Information | SP800-53 |
| nist-800-53:AU-9(1) | Hardware Write-once Media | SP800-53-enhancement |
| nist-800-53:AU-9(2) | Store on Separate Physical Systems or Components | SP800-53-enhancement |
| nist-800-53:AU-9(3) | Cryptographic Protection | SP800-53-enhancement |
| nist-800-53:AU-9(4) | Access by Subset of Privileged Users | SP800-53-enhancement |
| nist-800-53:AU-9(5) | Dual Authorization | SP800-53-enhancement |
| nist-800-53:AU-9(6) | Read-only Access | SP800-53-enhancement |
| nist-800-53:AU-9(7) | Store on Component with Different Operating System | SP800-53-enhancement |
| nist-800-53:CA | Assessment, Authorization, and Monitoring | family |
| nist-800-53:CA-1 | Policy and Procedures | SP800-53 |
| nist-800-53:CA-2 | Control Assessments | SP800-53 |
| nist-800-53:CA-2(1) | Independent Assessors | SP800-53-enhancement |
| nist-800-53:CA-2(2) | Specialized Assessments | SP800-53-enhancement |
| nist-800-53:CA-2(3) | Leveraging Results from External Organizations | SP800-53-enhancement |
| nist-800-53:CA-3 | Information Exchange | SP800-53 |
| nist-800-53:CA-3(1) | Unclassified National Security System Connections | SP800-53-enhancement (deprecated) |
| nist-800-53:CA-3(2) | Classified National Security System Connections | SP800-53-enhancement (deprecated) |
| nist-800-53:CA-3(3) | Unclassified Non-national Security System Connections | SP800-53-enhancement (deprecated) |
| nist-800-53:CA-3(4) | Connections to Public Networks | SP800-53-enhancement (deprecated) |
| nist-800-53:CA-3(5) | Restrictions on External System Connections | SP800-53-enhancement (deprecated) |
| nist-800-53:CA-3(6) | Transfer Authorizations | SP800-53-enhancement |
| nist-800-53:CA-3(7) | Transitive Information Exchanges | SP800-53-enhancement |
| nist-800-53:CA-4 | Security Certification | SP800-53 (deprecated) |
| nist-800-53:CA-5 | Plan of Action and Milestones | SP800-53 |
| nist-800-53:CA-5(1) | Automation Support for Accuracy and Currency | SP800-53-enhancement |
| nist-800-53:CA-6 | Authorization | SP800-53 |
| nist-800-53:CA-6(1) | Joint Authorization — Intra-organization | SP800-53-enhancement |
| nist-800-53:CA-6(2) | Joint Authorization — Inter-organization | SP800-53-enhancement |
| nist-800-53:CA-7 | Continuous Monitoring | SP800-53 |
| nist-800-53:CA-7(1) | Independent Assessment | SP800-53-enhancement |
| nist-800-53:CA-7(2) | Types of Assessments | SP800-53-enhancement (deprecated) |
| nist-800-53:CA-7(3) | Trend Analyses | SP800-53-enhancement |
| nist-800-53:CA-7(4) | Risk Monitoring | SP800-53-enhancement |
| nist-800-53:CA-7(5) | Consistency Analysis | SP800-53-enhancement |
| nist-800-53:CA-7(6) | Automation Support for Monitoring | SP800-53-enhancement |
| nist-800-53:CA-8 | Penetration Testing | SP800-53 |
| nist-800-53:CA-8(1) | Independent Penetration Testing Agent or Team | SP800-53-enhancement |
| nist-800-53:CA-8(2) | Red Team Exercises | SP800-53-enhancement |
| nist-800-53:CA-8(3) | Facility Penetration Testing | SP800-53-enhancement |
| nist-800-53:CA-9 | Internal System Connections | SP800-53 |
| nist-800-53:CA-9(1) | Compliance Checks | SP800-53-enhancement |
| nist-800-53:CM | Configuration Management | family |
| nist-800-53:CM-1 | Policy and Procedures | SP800-53 |
| nist-800-53:CM-10 | Software Usage Restrictions | SP800-53 |
| nist-800-53:CM-10(1) | Open-source Software | SP800-53-enhancement |
| nist-800-53:CM-11 | User-installed Software | SP800-53 |
| nist-800-53:CM-11(1) | Alerts for Unauthorized Installations | SP800-53-enhancement (deprecated) |
| nist-800-53:CM-11(2) | Software Installation with Privileged Status | SP800-53-enhancement |
| nist-800-53:CM-11(3) | Automated Enforcement and Monitoring | SP800-53-enhancement |
| nist-800-53:CM-12 | Information Location | SP800-53 |
| nist-800-53:CM-12(1) | Automated Tools to Support Information Location | SP800-53-enhancement |
| nist-800-53:CM-13 | Data Action Mapping | SP800-53 |
| nist-800-53:CM-14 | Signed Components | SP800-53 |
| nist-800-53:CM-2 | Baseline Configuration | SP800-53 |
| nist-800-53:CM-2(1) | Reviews and Updates | SP800-53-enhancement (deprecated) |
| nist-800-53:CM-2(2) | Automation Support for Accuracy and Currency | SP800-53-enhancement |
| nist-800-53:CM-2(3) | Retention of Previous Configurations | SP800-53-enhancement |
| nist-800-53:CM-2(4) | Unauthorized Software | SP800-53-enhancement (deprecated) |
| nist-800-53:CM-2(5) | Authorized Software | SP800-53-enhancement (deprecated) |
| nist-800-53:CM-2(6) | Development and Test Environments | SP800-53-enhancement |
| nist-800-53:CM-2(7) | Configure Systems and Components for High-risk Areas | SP800-53-enhancement |
| nist-800-53:CM-3 | Configuration Change Control | SP800-53 |
| nist-800-53:CM-3(1) | Automated Documentation, Notification, and Prohibition of Changes | SP800-53-enhancement |
| nist-800-53:CM-3(2) | Testing, Validation, and Documentation of Changes | SP800-53-enhancement |
| nist-800-53:CM-3(3) | Automated Change Implementation | SP800-53-enhancement |
| nist-800-53:CM-3(4) | Security and Privacy Representatives | SP800-53-enhancement |
| nist-800-53:CM-3(5) | Automated Security Response | SP800-53-enhancement |
| nist-800-53:CM-3(6) | Cryptography Management | SP800-53-enhancement |
| nist-800-53:CM-3(7) | Review System Changes | SP800-53-enhancement |
| nist-800-53:CM-3(8) | Prevent or Restrict Configuration Changes | SP800-53-enhancement |
| nist-800-53:CM-4 | Impact Analyses | SP800-53 |
| nist-800-53:CM-4(1) | Separate Test Environments | SP800-53-enhancement |
| nist-800-53:CM-4(2) | Verification of Controls | SP800-53-enhancement |
| nist-800-53:CM-5 | Access Restrictions for Change | SP800-53 |
| nist-800-53:CM-5(1) | Automated Access Enforcement and Audit Records | SP800-53-enhancement |
| nist-800-53:CM-5(2) | Review System Changes | SP800-53-enhancement (deprecated) |
| nist-800-53:CM-5(3) | Signed Components | SP800-53-enhancement (deprecated) |
| nist-800-53:CM-5(4) | Dual Authorization | SP800-53-enhancement |
| nist-800-53:CM-5(5) | Privilege Limitation for Production and Operation | SP800-53-enhancement |
| nist-800-53:CM-5(6) | Limit Library Privileges | SP800-53-enhancement |
| nist-800-53:CM-5(7) | Automatic Implementation of Security Safeguards | SP800-53-enhancement (deprecated) |
| nist-800-53:CM-6 | Configuration Settings | SP800-53 |
| nist-800-53:CM-6(1) | Automated Management, Application, and Verification | SP800-53-enhancement |
| nist-800-53:CM-6(2) | Respond to Unauthorized Changes | SP800-53-enhancement |
| nist-800-53:CM-6(3) | Unauthorized Change Detection | SP800-53-enhancement (deprecated) |
| nist-800-53:CM-6(4) | Conformance Demonstration | SP800-53-enhancement (deprecated) |
| nist-800-53:CM-7 | Least Functionality | SP800-53 |
| nist-800-53:CM-7(1) | Periodic Review | SP800-53-enhancement |
| nist-800-53:CM-7(2) | Prevent Program Execution | SP800-53-enhancement |
| nist-800-53:CM-7(3) | Registration Compliance | SP800-53-enhancement |
| nist-800-53:CM-7(4) | Unauthorized Software — Deny-by-exception | SP800-53-enhancement |
| nist-800-53:CM-7(5) | Authorized Software — Allow-by-exception | SP800-53-enhancement |
| nist-800-53:CM-7(6) | Confined Environments with Limited Privileges | SP800-53-enhancement |
| nist-800-53:CM-7(7) | Code Execution in Protected Environments | SP800-53-enhancement |
| nist-800-53:CM-7(8) | Binary or Machine Executable Code | SP800-53-enhancement |
| nist-800-53:CM-7(9) | Prohibiting The Use of Unauthorized Hardware | SP800-53-enhancement |
| nist-800-53:CM-8 | System Component Inventory | SP800-53 |
| nist-800-53:CM-8(1) | Updates During Installation and Removal | SP800-53-enhancement |
| nist-800-53:CM-8(2) | Automated Maintenance | SP800-53-enhancement |
| nist-800-53:CM-8(3) | Automated Unauthorized Component Detection | SP800-53-enhancement |
| nist-800-53:CM-8(4) | Accountability Information | SP800-53-enhancement |
| nist-800-53:CM-8(5) | No Duplicate Accounting of Components | SP800-53-enhancement (deprecated) |
| nist-800-53:CM-8(6) | Assessed Configurations and Approved Deviations | SP800-53-enhancement |
| nist-800-53:CM-8(7) | Centralized Repository | SP800-53-enhancement |
| nist-800-53:CM-8(8) | Automated Location Tracking | SP800-53-enhancement |
| nist-800-53:CM-8(9) | Assignment of Components to Systems | SP800-53-enhancement |
| nist-800-53:CM-9 | Configuration Management Plan | SP800-53 |
| nist-800-53:CM-9(1) | Assignment of Responsibility | SP800-53-enhancement |
| nist-800-53:CP | Contingency Planning | family |
| nist-800-53:CP-1 | Policy and Procedures | SP800-53 |
| nist-800-53:CP-10 | System Recovery and Reconstitution | SP800-53 |
| nist-800-53:CP-10(1) | Contingency Plan Testing | SP800-53-enhancement (deprecated) |
| nist-800-53:CP-10(2) | Transaction Recovery | SP800-53-enhancement |
| nist-800-53:CP-10(3) | Compensating Security Controls | SP800-53-enhancement (deprecated) |
| nist-800-53:CP-10(4) | Restore Within Time Period | SP800-53-enhancement |
| nist-800-53:CP-10(5) | Failover Capability | SP800-53-enhancement (deprecated) |
| nist-800-53:CP-10(6) | Component Protection | SP800-53-enhancement |
| nist-800-53:CP-11 | Alternate Communications Protocols | SP800-53 |
| nist-800-53:CP-12 | Safe Mode | SP800-53 |
| nist-800-53:CP-13 | Alternative Security Mechanisms | SP800-53 |
| nist-800-53:CP-2 | Contingency Plan | SP800-53 |
| nist-800-53:CP-2(1) | Coordinate with Related Plans | SP800-53-enhancement |
| nist-800-53:CP-2(2) | Capacity Planning | SP800-53-enhancement |
| nist-800-53:CP-2(3) | Resume Mission and Business Functions | SP800-53-enhancement |
| nist-800-53:CP-2(4) | Resume All Mission and Business Functions | SP800-53-enhancement (deprecated) |
| nist-800-53:CP-2(5) | Continue Mission and Business Functions | SP800-53-enhancement |
| nist-800-53:CP-2(6) | Alternate Processing and Storage Sites | SP800-53-enhancement |
| nist-800-53:CP-2(7) | Coordinate with External Service Providers | SP800-53-enhancement |
| nist-800-53:CP-2(8) | Identify Critical Assets | SP800-53-enhancement |
| nist-800-53:CP-3 | Contingency Training | SP800-53 |
| nist-800-53:CP-3(1) | Simulated Events | SP800-53-enhancement |
| nist-800-53:CP-3(2) | Mechanisms Used in Training Environments | SP800-53-enhancement |
| nist-800-53:CP-4 | Contingency Plan Testing | SP800-53 |
| nist-800-53:CP-4(1) | Coordinate with Related Plans | SP800-53-enhancement |
| nist-800-53:CP-4(2) | Alternate Processing Site | SP800-53-enhancement |
| nist-800-53:CP-4(3) | Automated Testing | SP800-53-enhancement |
| nist-800-53:CP-4(4) | Full Recovery and Reconstitution | SP800-53-enhancement |
| nist-800-53:CP-4(5) | Self-challenge | SP800-53-enhancement |
| nist-800-53:CP-5 | Contingency Plan Update | SP800-53 (deprecated) |
| nist-800-53:CP-6 | Alternate Storage Site | SP800-53 |
| nist-800-53:CP-6(1) | Separation from Primary Site | SP800-53-enhancement |
| nist-800-53:CP-6(2) | Recovery Time and Recovery Point Objectives | SP800-53-enhancement |
| nist-800-53:CP-6(3) | Accessibility | SP800-53-enhancement |
| nist-800-53:CP-7 | Alternate Processing Site | SP800-53 |
| nist-800-53:CP-7(1) | Separation from Primary Site | SP800-53-enhancement |
| nist-800-53:CP-7(2) | Accessibility | SP800-53-enhancement |
| nist-800-53:CP-7(3) | Priority of Service | SP800-53-enhancement |
| nist-800-53:CP-7(4) | Preparation for Use | SP800-53-enhancement |
| nist-800-53:CP-7(5) | Equivalent Information Security Safeguards | SP800-53-enhancement (deprecated) |
| nist-800-53:CP-7(6) | Inability to Return to Primary Site | SP800-53-enhancement |
| nist-800-53:CP-8 | Telecommunications Services | SP800-53 |
| nist-800-53:CP-8(1) | Priority of Service Provisions | SP800-53-enhancement |
| nist-800-53:CP-8(2) | Single Points of Failure | SP800-53-enhancement |
| nist-800-53:CP-8(3) | Separation of Primary and Alternate Providers | SP800-53-enhancement |
| nist-800-53:CP-8(4) | Provider Contingency Plan | SP800-53-enhancement |
| nist-800-53:CP-8(5) | Alternate Telecommunication Service Testing | SP800-53-enhancement |
| nist-800-53:CP-9 | System Backup | SP800-53 |
| nist-800-53:CP-9(1) | Testing for Reliability and Integrity | SP800-53-enhancement |
| nist-800-53:CP-9(2) | Test Restoration Using Sampling | SP800-53-enhancement |
| nist-800-53:CP-9(3) | Separate Storage for Critical Information | SP800-53-enhancement |
| nist-800-53:CP-9(4) | Protection from Unauthorized Modification | SP800-53-enhancement (deprecated) |
| nist-800-53:CP-9(5) | Transfer to Alternate Storage Site | SP800-53-enhancement |
| nist-800-53:CP-9(6) | Redundant Secondary System | SP800-53-enhancement |
| nist-800-53:CP-9(7) | Dual Authorization for Deletion or Destruction | SP800-53-enhancement |
| nist-800-53:CP-9(8) | Cryptographic Protection | SP800-53-enhancement |
| nist-800-53:IA | Identification and Authentication | family |
| nist-800-53:IA-1 | Policy and Procedures | SP800-53 |
| nist-800-53:IA-10 | Adaptive Authentication | SP800-53 |
| nist-800-53:IA-11 | Re-authentication | SP800-53 |
| nist-800-53:IA-12 | Identity Proofing | SP800-53 |
| nist-800-53:IA-12(1) | Supervisor Authorization | SP800-53-enhancement |
| nist-800-53:IA-12(2) | Identity Evidence | SP800-53-enhancement |
| nist-800-53:IA-12(3) | Identity Evidence Validation and Verification | SP800-53-enhancement |
| nist-800-53:IA-12(4) | In-person Validation and Verification | SP800-53-enhancement |
| nist-800-53:IA-12(5) | Address Confirmation | SP800-53-enhancement |
| nist-800-53:IA-12(6) | Accept Externally-proofed Identities | SP800-53-enhancement |
| nist-800-53:IA-13 | Identity Providers and Authorization Servers | SP800-53 |
| nist-800-53:IA-13(1) | Protection of Cryptographic Keys | SP800-53-enhancement |
| nist-800-53:IA-13(2) | Verification of Identity Assertions and Access Tokens | SP800-53-enhancement |
| nist-800-53:IA-13(3) | Token Management | SP800-53-enhancement |
| nist-800-53:IA-2 | Identification and Authentication (Organizational Users) | SP800-53 |
| nist-800-53:IA-2(1) | Multi-factor Authentication to Privileged Accounts | SP800-53-enhancement |
| nist-800-53:IA-2(10) | Single Sign-on | SP800-53-enhancement |
| nist-800-53:IA-2(11) | Remote Access — Separate Device | SP800-53-enhancement (deprecated) |
| nist-800-53:IA-2(12) | Acceptance of PIV Credentials | SP800-53-enhancement |
| nist-800-53:IA-2(13) | Out-of-band Authentication | SP800-53-enhancement |
| nist-800-53:IA-2(2) | Multi-factor Authentication to Non-privileged Accounts | SP800-53-enhancement |
| nist-800-53:IA-2(3) | Local Access to Privileged Accounts | SP800-53-enhancement (deprecated) |
| nist-800-53:IA-2(4) | Local Access to Non-privileged Accounts | SP800-53-enhancement (deprecated) |
| nist-800-53:IA-2(5) | Individual Authentication with Group Authentication | SP800-53-enhancement |
| nist-800-53:IA-2(6) | Access to Accounts —separate Device | SP800-53-enhancement |
| nist-800-53:IA-2(7) | Network Access to Non-privileged Accounts — Separate Device | SP800-53-enhancement (deprecated) |
| nist-800-53:IA-2(8) | Access to Accounts — Replay Resistant | SP800-53-enhancement |
| nist-800-53:IA-2(9) | Network Access to Non-privileged Accounts — Replay Resistant | SP800-53-enhancement (deprecated) |
| nist-800-53:IA-3 | Device Identification and Authentication | SP800-53 |
| nist-800-53:IA-3(1) | Cryptographic Bidirectional Authentication | SP800-53-enhancement |
| nist-800-53:IA-3(2) | Cryptographic Bidirectional Network Authentication | SP800-53-enhancement (deprecated) |
| nist-800-53:IA-3(3) | Dynamic Address Allocation | SP800-53-enhancement |
| nist-800-53:IA-3(4) | Device Attestation | SP800-53-enhancement |
| nist-800-53:IA-4 | Identifier Management | SP800-53 |
| nist-800-53:IA-4(1) | Prohibit Account Identifiers as Public Identifiers | SP800-53-enhancement |
| nist-800-53:IA-4(2) | Supervisor Authorization | SP800-53-enhancement (deprecated) |
| nist-800-53:IA-4(3) | Multiple Forms of Certification | SP800-53-enhancement (deprecated) |
| nist-800-53:IA-4(4) | Identify User Status | SP800-53-enhancement |
| nist-800-53:IA-4(5) | Dynamic Management | SP800-53-enhancement |
| nist-800-53:IA-4(6) | Cross-organization Management | SP800-53-enhancement |
| nist-800-53:IA-4(7) | In-person Registration | SP800-53-enhancement (deprecated) |
| nist-800-53:IA-4(8) | Pairwise Pseudonymous Identifiers | SP800-53-enhancement |
| nist-800-53:IA-4(9) | Attribute Maintenance and Protection | SP800-53-enhancement |
| nist-800-53:IA-5 | Authenticator Management | SP800-53 |
| nist-800-53:IA-5(1) | Password-based Authentication | SP800-53-enhancement |
| nist-800-53:IA-5(10) | Dynamic Credential Binding | SP800-53-enhancement |
| nist-800-53:IA-5(11) | Hardware Token-based Authentication | SP800-53-enhancement (deprecated) |
| nist-800-53:IA-5(12) | Biometric Authentication Performance | SP800-53-enhancement |
| nist-800-53:IA-5(13) | Expiration of Cached Authenticators | SP800-53-enhancement |
| nist-800-53:IA-5(14) | Managing Content of PKI Trust Stores | SP800-53-enhancement |
| nist-800-53:IA-5(15) | GSA-approved Products and Services | SP800-53-enhancement |
| nist-800-53:IA-5(16) | In-person or Trusted External Party Authenticator Issuance | SP800-53-enhancement |
| nist-800-53:IA-5(17) | Presentation Attack Detection for Biometric Authenticators | SP800-53-enhancement |
| nist-800-53:IA-5(18) | Password Managers | SP800-53-enhancement |
| nist-800-53:IA-5(2) | Public Key-based Authentication | SP800-53-enhancement |
| nist-800-53:IA-5(3) | In-person or Trusted External Party Registration | SP800-53-enhancement (deprecated) |
| nist-800-53:IA-5(4) | Automated Support for Password Strength Determination | SP800-53-enhancement (deprecated) |
| nist-800-53:IA-5(5) | Change Authenticators Prior to Delivery | SP800-53-enhancement |
| nist-800-53:IA-5(6) | Protection of Authenticators | SP800-53-enhancement |
| nist-800-53:IA-5(7) | No Embedded Unencrypted Static Authenticators | SP800-53-enhancement |
| nist-800-53:IA-5(8) | Multiple System Accounts | SP800-53-enhancement |
| nist-800-53:IA-5(9) | Federated Credential Management | SP800-53-enhancement |
| nist-800-53:IA-6 | Authentication Feedback | SP800-53 |
| nist-800-53:IA-7 | Cryptographic Module Authentication | SP800-53 |
| nist-800-53:IA-8 | Identification and Authentication (Non-organizational Users) | SP800-53 |
| nist-800-53:IA-8(1) | Acceptance of PIV Credentials from Other Agencies | SP800-53-enhancement |
| nist-800-53:IA-8(2) | Acceptance of External Authenticators | SP800-53-enhancement |
| nist-800-53:IA-8(3) | Use of FICAM-approved Products | SP800-53-enhancement (deprecated) |
| nist-800-53:IA-8(4) | Use of Defined Profiles | SP800-53-enhancement |
| nist-800-53:IA-8(5) | Acceptance of PIV-I Credentials | SP800-53-enhancement |
| nist-800-53:IA-8(6) | Disassociability | SP800-53-enhancement |
| nist-800-53:IA-9 | Service Identification and Authentication | SP800-53 |
| nist-800-53:IA-9(1) | Information Exchange | SP800-53-enhancement (deprecated) |
| nist-800-53:IA-9(2) | Transmission of Decisions | SP800-53-enhancement (deprecated) |
| nist-800-53:IR | Incident Response | family |
| nist-800-53:IR-1 | Policy and Procedures | SP800-53 |
| nist-800-53:IR-10 | Integrated Information Security Analysis Team | SP800-53 (deprecated) |
| nist-800-53:IR-2 | Incident Response Training | SP800-53 |
| nist-800-53:IR-2(1) | Simulated Events | SP800-53-enhancement |
| nist-800-53:IR-2(2) | Automated Training Environments | SP800-53-enhancement |
| nist-800-53:IR-2(3) | Breach | SP800-53-enhancement |
| nist-800-53:IR-3 | Incident Response Testing | SP800-53 |
| nist-800-53:IR-3(1) | Automated Testing | SP800-53-enhancement |
| nist-800-53:IR-3(2) | Coordination with Related Plans | SP800-53-enhancement |
| nist-800-53:IR-3(3) | Continuous Improvement | SP800-53-enhancement |
| nist-800-53:IR-4 | Incident Handling | SP800-53 |
| nist-800-53:IR-4(1) | Automated Incident Handling Processes | SP800-53-enhancement |
| nist-800-53:IR-4(10) | Supply Chain Coordination | SP800-53-enhancement |
| nist-800-53:IR-4(11) | Integrated Incident Response Team | SP800-53-enhancement |
| nist-800-53:IR-4(12) | Malicious Code and Forensic Analysis | SP800-53-enhancement |
| nist-800-53:IR-4(13) | Behavior Analysis | SP800-53-enhancement |
| nist-800-53:IR-4(14) | Security Operations Center | SP800-53-enhancement |
| nist-800-53:IR-4(15) | Public Relations and Reputation Repair | SP800-53-enhancement |
| nist-800-53:IR-4(2) | Dynamic Reconfiguration | SP800-53-enhancement |
| nist-800-53:IR-4(3) | Continuity of Operations | SP800-53-enhancement |
| nist-800-53:IR-4(4) | Information Correlation | SP800-53-enhancement |
| nist-800-53:IR-4(5) | Automatic Disabling of System | SP800-53-enhancement |
| nist-800-53:IR-4(6) | Insider Threats | SP800-53-enhancement |
| nist-800-53:IR-4(7) | Insider Threats — Intra-organization Coordination | SP800-53-enhancement |
| nist-800-53:IR-4(8) | Correlation with External Organizations | SP800-53-enhancement |
| nist-800-53:IR-4(9) | Dynamic Response Capability | SP800-53-enhancement |
| nist-800-53:IR-5 | Incident Monitoring | SP800-53 |
| nist-800-53:IR-5(1) | Automated Tracking, Data Collection, and Analysis | SP800-53-enhancement |
| nist-800-53:IR-6 | Incident Reporting | SP800-53 |
| nist-800-53:IR-6(1) | Automated Reporting | SP800-53-enhancement |
| nist-800-53:IR-6(2) | Vulnerabilities Related to Incidents | SP800-53-enhancement |
| nist-800-53:IR-6(3) | Supply Chain Coordination | SP800-53-enhancement |
| nist-800-53:IR-7 | Incident Response Assistance | SP800-53 |
| nist-800-53:IR-7(1) | Automation Support for Availability of Information and Support | SP800-53-enhancement |
| nist-800-53:IR-7(2) | Coordination with External Providers | SP800-53-enhancement |
| nist-800-53:IR-8 | Incident Response Plan | SP800-53 |
| nist-800-53:IR-8(1) | Breaches | SP800-53-enhancement |
| nist-800-53:IR-9 | Information Spillage Response | SP800-53 |
| nist-800-53:IR-9(1) | Responsible Personnel | SP800-53-enhancement (deprecated) |
| nist-800-53:IR-9(2) | Training | SP800-53-enhancement |
| nist-800-53:IR-9(3) | Post-spill Operations | SP800-53-enhancement |
| nist-800-53:IR-9(4) | Exposure to Unauthorized Personnel | SP800-53-enhancement |
| nist-800-53:MA | Maintenance | family |
| nist-800-53:MA-1 | Policy and Procedures | SP800-53 |
| nist-800-53:MA-2 | Controlled Maintenance | SP800-53 |
| nist-800-53:MA-2(1) | Record Content | SP800-53-enhancement (deprecated) |
| nist-800-53:MA-2(2) | Automated Maintenance Activities | SP800-53-enhancement |
| nist-800-53:MA-3 | Maintenance Tools | SP800-53 |
| nist-800-53:MA-3(1) | Inspect Tools | SP800-53-enhancement |
| nist-800-53:MA-3(2) | Inspect Media | SP800-53-enhancement |
| nist-800-53:MA-3(3) | Prevent Unauthorized Removal | SP800-53-enhancement |
| nist-800-53:MA-3(4) | Restricted Tool Use | SP800-53-enhancement |
| nist-800-53:MA-3(5) | Execution with Privilege | SP800-53-enhancement |
| nist-800-53:MA-3(6) | Software Updates and Patches | SP800-53-enhancement |
| nist-800-53:MA-4 | Nonlocal Maintenance | SP800-53 |
| nist-800-53:MA-4(1) | Logging and Review | SP800-53-enhancement |
| nist-800-53:MA-4(2) | Document Nonlocal Maintenance | SP800-53-enhancement (deprecated) |
| nist-800-53:MA-4(3) | Comparable Security and Sanitization | SP800-53-enhancement |
| nist-800-53:MA-4(4) | Authentication and Separation of Maintenance Sessions | SP800-53-enhancement |
| nist-800-53:MA-4(5) | Approvals and Notifications | SP800-53-enhancement |
| nist-800-53:MA-4(6) | Cryptographic Protection | SP800-53-enhancement |
| nist-800-53:MA-4(7) | Disconnect Verification | SP800-53-enhancement |
| nist-800-53:MA-5 | Maintenance Personnel | SP800-53 |
| nist-800-53:MA-5(1) | Individuals Without Appropriate Access | SP800-53-enhancement |
| nist-800-53:MA-5(2) | Security Clearances for Classified Systems | SP800-53-enhancement |
| nist-800-53:MA-5(3) | Citizenship Requirements for Classified Systems | SP800-53-enhancement |
| nist-800-53:MA-5(4) | Foreign Nationals | SP800-53-enhancement |
| nist-800-53:MA-5(5) | Non-system Maintenance | SP800-53-enhancement |
| nist-800-53:MA-6 | Timely Maintenance | SP800-53 |
| nist-800-53:MA-6(1) | Preventive Maintenance | SP800-53-enhancement |
| nist-800-53:MA-6(2) | Predictive Maintenance | SP800-53-enhancement |
| nist-800-53:MA-6(3) | Automated Support for Predictive Maintenance | SP800-53-enhancement |
| nist-800-53:MA-7 | Field Maintenance | SP800-53 |
| nist-800-53:MP | Media Protection | family |
| nist-800-53:MP-1 | Policy and Procedures | SP800-53 |
| nist-800-53:MP-2 | Media Access | SP800-53 |
| nist-800-53:MP-2(1) | Automated Restricted Access | SP800-53-enhancement (deprecated) |
| nist-800-53:MP-2(2) | Cryptographic Protection | SP800-53-enhancement (deprecated) |
| nist-800-53:MP-3 | Media Marking | SP800-53 |
| nist-800-53:MP-4 | Media Storage | SP800-53 |
| nist-800-53:MP-4(1) | Cryptographic Protection | SP800-53-enhancement (deprecated) |
| nist-800-53:MP-4(2) | Automated Restricted Access | SP800-53-enhancement |
| nist-800-53:MP-5 | Media Transport | SP800-53 |
| nist-800-53:MP-5(1) | Protection Outside of Controlled Areas | SP800-53-enhancement (deprecated) |
| nist-800-53:MP-5(2) | Documentation of Activities | SP800-53-enhancement (deprecated) |
| nist-800-53:MP-5(3) | Custodians | SP800-53-enhancement |
| nist-800-53:MP-5(4) | Cryptographic Protection | SP800-53-enhancement (deprecated) |
| nist-800-53:MP-6 | Media Sanitization | SP800-53 |
| nist-800-53:MP-6(1) | Review, Approve, Track, Document, and Verify | SP800-53-enhancement |
| nist-800-53:MP-6(2) | Equipment Testing | SP800-53-enhancement |
| nist-800-53:MP-6(3) | Nondestructive Techniques | SP800-53-enhancement |
| nist-800-53:MP-6(4) | Controlled Unclassified Information | SP800-53-enhancement (deprecated) |
| nist-800-53:MP-6(5) | Classified Information | SP800-53-enhancement (deprecated) |
| nist-800-53:MP-6(6) | Media Destruction | SP800-53-enhancement (deprecated) |
| nist-800-53:MP-6(7) | Dual Authorization | SP800-53-enhancement |
| nist-800-53:MP-6(8) | Remote Purging or Wiping of Information | SP800-53-enhancement |
| nist-800-53:MP-7 | Media Use | SP800-53 |
| nist-800-53:MP-7(1) | Prohibit Use Without Owner | SP800-53-enhancement (deprecated) |
| nist-800-53:MP-7(2) | Prohibit Use of Sanitization-resistant Media | SP800-53-enhancement |
| nist-800-53:MP-8 | Media Downgrading | SP800-53 |
| nist-800-53:MP-8(1) | Documentation of Process | SP800-53-enhancement |
| nist-800-53:MP-8(2) | Equipment Testing | SP800-53-enhancement |
| nist-800-53:MP-8(3) | Controlled Unclassified Information | SP800-53-enhancement |
| nist-800-53:MP-8(4) | Classified Information | SP800-53-enhancement |
| nist-800-53:PE | Physical and Environmental Protection | family |
| nist-800-53:PE-1 | Policy and Procedures | SP800-53 |
| nist-800-53:PE-10 | Emergency Shutoff | SP800-53 |
| nist-800-53:PE-10(1) | Accidental and Unauthorized Activation | SP800-53-enhancement (deprecated) |
| nist-800-53:PE-11 | Emergency Power | SP800-53 |
| nist-800-53:PE-11(1) | Alternate Power Supply — Minimal Operational Capability | SP800-53-enhancement |
| nist-800-53:PE-11(2) | Alternate Power Supply — Self-contained | SP800-53-enhancement |
| nist-800-53:PE-12 | Emergency Lighting | SP800-53 |
| nist-800-53:PE-12(1) | Essential Mission and Business Functions | SP800-53-enhancement |
| nist-800-53:PE-13 | Fire Protection | SP800-53 |
| nist-800-53:PE-13(1) | Detection Systems — Automatic Activation and Notification | SP800-53-enhancement |
| nist-800-53:PE-13(2) | Suppression Systems — Automatic Activation and Notification | SP800-53-enhancement |
| nist-800-53:PE-13(3) | Automatic Fire Suppression | SP800-53-enhancement (deprecated) |
| nist-800-53:PE-13(4) | Inspections | SP800-53-enhancement |
| nist-800-53:PE-14 | Environmental Controls | SP800-53 |
| nist-800-53:PE-14(1) | Automatic Controls | SP800-53-enhancement |
| nist-800-53:PE-14(2) | Monitoring with Alarms and Notifications | SP800-53-enhancement |
| nist-800-53:PE-15 | Water Damage Protection | SP800-53 |
| nist-800-53:PE-15(1) | Automation Support | SP800-53-enhancement |
| nist-800-53:PE-16 | Delivery and Removal | SP800-53 |
| nist-800-53:PE-17 | Alternate Work Site | SP800-53 |
| nist-800-53:PE-18 | Location of System Components | SP800-53 |
| nist-800-53:PE-18(1) | Facility Site | SP800-53-enhancement (deprecated) |
| nist-800-53:PE-19 | Information Leakage | SP800-53 |
| nist-800-53:PE-19(1) | National Emissions Policies and Procedures | SP800-53-enhancement |
| nist-800-53:PE-2 | Physical Access Authorizations | SP800-53 |
| nist-800-53:PE-2(1) | Access by Position or Role | SP800-53-enhancement |
| nist-800-53:PE-2(2) | Two Forms of Identification | SP800-53-enhancement |
| nist-800-53:PE-2(3) | Restrict Unescorted Access | SP800-53-enhancement |
| nist-800-53:PE-20 | Asset Monitoring and Tracking | SP800-53 |
| nist-800-53:PE-21 | Electromagnetic Pulse Protection | SP800-53 |
| nist-800-53:PE-22 | Component Marking | SP800-53 |
| nist-800-53:PE-23 | Facility Location | SP800-53 |
| nist-800-53:PE-3 | Physical Access Control | SP800-53 |
| nist-800-53:PE-3(1) | System Access | SP800-53-enhancement |
| nist-800-53:PE-3(2) | Facility and Systems | SP800-53-enhancement |
| nist-800-53:PE-3(3) | Continuous Guards | SP800-53-enhancement |
| nist-800-53:PE-3(4) | Lockable Casings | SP800-53-enhancement |
| nist-800-53:PE-3(5) | Tamper Protection | SP800-53-enhancement |
| nist-800-53:PE-3(6) | Facility Penetration Testing | SP800-53-enhancement (deprecated) |
| nist-800-53:PE-3(7) | Physical Barriers | SP800-53-enhancement |
| nist-800-53:PE-3(8) | Access Control Vestibules | SP800-53-enhancement |
| nist-800-53:PE-4 | Access Control for Transmission | SP800-53 |
| nist-800-53:PE-5 | Access Control for Output Devices | SP800-53 |
| nist-800-53:PE-5(1) | Access to Output by Authorized Individuals | SP800-53-enhancement (deprecated) |
| nist-800-53:PE-5(2) | Link to Individual Identity | SP800-53-enhancement |
| nist-800-53:PE-5(3) | Marking Output Devices | SP800-53-enhancement (deprecated) |
| nist-800-53:PE-6 | Monitoring Physical Access | SP800-53 |
| nist-800-53:PE-6(1) | Intrusion Alarms and Surveillance Equipment | SP800-53-enhancement |
| nist-800-53:PE-6(2) | Automated Intrusion Recognition and Responses | SP800-53-enhancement |
| nist-800-53:PE-6(3) | Video Surveillance | SP800-53-enhancement |
| nist-800-53:PE-6(4) | Monitoring Physical Access to Systems | SP800-53-enhancement |
| nist-800-53:PE-7 | Visitor Control | SP800-53 (deprecated) |
| nist-800-53:PE-8 | Visitor Access Records | SP800-53 |
| nist-800-53:PE-8(1) | Automated Records Maintenance and Review | SP800-53-enhancement |
| nist-800-53:PE-8(2) | Physical Access Records | SP800-53-enhancement (deprecated) |
| nist-800-53:PE-8(3) | Limit Personally Identifiable Information Elements | SP800-53-enhancement |
| nist-800-53:PE-9 | Power Equipment and Cabling | SP800-53 |
| nist-800-53:PE-9(1) | Redundant Cabling | SP800-53-enhancement |
| nist-800-53:PE-9(2) | Automatic Voltage Controls | SP800-53-enhancement |
| nist-800-53:PL | Planning | family |
| nist-800-53:PL-1 | Policy and Procedures | SP800-53 |
| nist-800-53:PL-10 | Baseline Selection | SP800-53 |
| nist-800-53:PL-11 | Baseline Tailoring | SP800-53 |
| nist-800-53:PL-2 | System Security and Privacy Plans | SP800-53 |
| nist-800-53:PL-2(1) | Concept of Operations | SP800-53-enhancement (deprecated) |
| nist-800-53:PL-2(2) | Functional Architecture | SP800-53-enhancement (deprecated) |
| nist-800-53:PL-2(3) | Plan and Coordinate with Other Organizational Entities | SP800-53-enhancement (deprecated) |
| nist-800-53:PL-3 | System Security Plan Update | SP800-53 (deprecated) |
| nist-800-53:PL-4 | Rules of Behavior | SP800-53 |
| nist-800-53:PL-4(1) | Social Media and External Site/Application Usage Restrictions | SP800-53-enhancement |
| nist-800-53:PL-5 | Privacy Impact Assessment | SP800-53 (deprecated) |
| nist-800-53:PL-6 | Security-related Activity Planning | SP800-53 (deprecated) |
| nist-800-53:PL-7 | Concept of Operations | SP800-53 |
| nist-800-53:PL-8 | Security and Privacy Architectures | SP800-53 |
| nist-800-53:PL-8(1) | Defense in Depth | SP800-53-enhancement |
| nist-800-53:PL-8(2) | Supplier Diversity | SP800-53-enhancement |
| nist-800-53:PL-9 | Central Management | SP800-53 |
| nist-800-53:PM | Program Management | family |
| nist-800-53:PM-1 | Information Security Program Plan | SP800-53 |
| nist-800-53:PM-10 | Authorization Process | SP800-53 |
| nist-800-53:PM-11 | Mission and Business Process Definition | SP800-53 |
| nist-800-53:PM-12 | Insider Threat Program | SP800-53 |
| nist-800-53:PM-13 | Security and Privacy Workforce | SP800-53 |
| nist-800-53:PM-14 | Testing, Training, and Monitoring | SP800-53 |
| nist-800-53:PM-15 | Security and Privacy Groups and Associations | SP800-53 |
| nist-800-53:PM-16 | Threat Awareness Program | SP800-53 |
| nist-800-53:PM-16(1) | Automated Means for Sharing Threat Intelligence | SP800-53-enhancement |
| nist-800-53:PM-17 | Protecting Controlled Unclassified Information on External Systems | SP800-53 |
| nist-800-53:PM-18 | Privacy Program Plan | SP800-53 |
| nist-800-53:PM-19 | Privacy Program Leadership Role | SP800-53 |
| nist-800-53:PM-2 | Information Security Program Leadership Role | SP800-53 |
| nist-800-53:PM-20 | Dissemination of Privacy Program Information | SP800-53 |
| nist-800-53:PM-20(1) | Privacy Policies on Websites, Applications, and Digital Services | SP800-53-enhancement |
| nist-800-53:PM-21 | Accounting of Disclosures | SP800-53 |
| nist-800-53:PM-22 | Personally Identifiable Information Quality Management | SP800-53 |
| nist-800-53:PM-23 | Data Governance Body | SP800-53 |
| nist-800-53:PM-24 | Data Integrity Board | SP800-53 |
| nist-800-53:PM-25 | Minimization of Personally Identifiable Information Used in Testing, Training, and Research | SP800-53 |
| nist-800-53:PM-26 | Complaint Management | SP800-53 |
| nist-800-53:PM-27 | Privacy Reporting | SP800-53 |
| nist-800-53:PM-28 | Risk Framing | SP800-53 |
| nist-800-53:PM-29 | Risk Management Program Leadership Roles | SP800-53 |
| nist-800-53:PM-3 | Information Security and Privacy Resources | SP800-53 |
| nist-800-53:PM-30 | Supply Chain Risk Management Strategy | SP800-53 |
| nist-800-53:PM-30(1) | Suppliers of Critical or Mission-essential Items | SP800-53-enhancement |
| nist-800-53:PM-31 | Continuous Monitoring Strategy | SP800-53 |
| nist-800-53:PM-32 | Purposing | SP800-53 |
| nist-800-53:PM-4 | Plan of Action and Milestones Process | SP800-53 |
| nist-800-53:PM-5 | System Inventory | SP800-53 |
| nist-800-53:PM-5(1) | Inventory of Personally Identifiable Information | SP800-53-enhancement |
| nist-800-53:PM-6 | Measures of Performance | SP800-53 |
| nist-800-53:PM-7 | Enterprise Architecture | SP800-53 |
| nist-800-53:PM-7(1) | Offloading | SP800-53-enhancement |
| nist-800-53:PM-8 | Critical Infrastructure Plan | SP800-53 |
| nist-800-53:PM-9 | Risk Management Strategy | SP800-53 |
| nist-800-53:PS | Personnel Security | family |
| nist-800-53:PS-1 | Policy and Procedures | SP800-53 |
| nist-800-53:PS-2 | Position Risk Designation | SP800-53 |
| nist-800-53:PS-3 | Personnel Screening | SP800-53 |
| nist-800-53:PS-3(1) | Classified Information | SP800-53-enhancement |
| nist-800-53:PS-3(2) | Formal Indoctrination | SP800-53-enhancement |
| nist-800-53:PS-3(3) | Information Requiring Special Protective Measures | SP800-53-enhancement |
| nist-800-53:PS-3(4) | Citizenship Requirements | SP800-53-enhancement |
| nist-800-53:PS-4 | Personnel Termination | SP800-53 |
| nist-800-53:PS-4(1) | Post-employment Requirements | SP800-53-enhancement |
| nist-800-53:PS-4(2) | Automated Actions | SP800-53-enhancement |
| nist-800-53:PS-5 | Personnel Transfer | SP800-53 |
| nist-800-53:PS-6 | Access Agreements | SP800-53 |
| nist-800-53:PS-6(1) | Information Requiring Special Protection | SP800-53-enhancement (deprecated) |
| nist-800-53:PS-6(2) | Classified Information Requiring Special Protection | SP800-53-enhancement |
| nist-800-53:PS-6(3) | Post-employment Requirements | SP800-53-enhancement |
| nist-800-53:PS-7 | External Personnel Security | SP800-53 |
| nist-800-53:PS-8 | Personnel Sanctions | SP800-53 |
| nist-800-53:PS-9 | Position Descriptions | SP800-53 |
| nist-800-53:PT | Personally Identifiable Information Processing and Transparency | family |
| nist-800-53:PT-1 | Policy and Procedures | SP800-53 |
| nist-800-53:PT-2 | Authority to Process Personally Identifiable Information | SP800-53 |
| nist-800-53:PT-2(1) | Data Tagging | SP800-53-enhancement |
| nist-800-53:PT-2(2) | Automation | SP800-53-enhancement |
| nist-800-53:PT-3 | Personally Identifiable Information Processing Purposes | SP800-53 |
| nist-800-53:PT-3(1) | Data Tagging | SP800-53-enhancement |
| nist-800-53:PT-3(2) | Automation | SP800-53-enhancement |
| nist-800-53:PT-4 | Consent | SP800-53 |
| nist-800-53:PT-4(1) | Tailored Consent | SP800-53-enhancement |
| nist-800-53:PT-4(2) | Just-in-time Consent | SP800-53-enhancement |
| nist-800-53:PT-4(3) | Revocation | SP800-53-enhancement |
| nist-800-53:PT-5 | Privacy Notice | SP800-53 |
| nist-800-53:PT-5(1) | Just-in-time Notice | SP800-53-enhancement |
| nist-800-53:PT-5(2) | Privacy Act Statements | SP800-53-enhancement |
| nist-800-53:PT-6 | System of Records Notice | SP800-53 |
| nist-800-53:PT-6(1) | Routine Uses | SP800-53-enhancement |
| nist-800-53:PT-6(2) | Exemption Rules | SP800-53-enhancement |
| nist-800-53:PT-7 | Specific Categories of Personally Identifiable Information | SP800-53 |
| nist-800-53:PT-7(1) | Social Security Numbers | SP800-53-enhancement |
| nist-800-53:PT-7(2) | First Amendment Information | SP800-53-enhancement |
| nist-800-53:PT-8 | Computer Matching Requirements | SP800-53 |
| nist-800-53:RA | Risk Assessment | family |
| nist-800-53:RA-1 | Policy and Procedures | SP800-53 |
| nist-800-53:RA-10 | Threat Hunting | SP800-53 |
| nist-800-53:RA-2 | Security Categorization | SP800-53 |
| nist-800-53:RA-2(1) | Impact-level Prioritization | SP800-53-enhancement |
| nist-800-53:RA-3 | Risk Assessment | SP800-53 |
| nist-800-53:RA-3(1) | Supply Chain Risk Assessment | SP800-53-enhancement |
| nist-800-53:RA-3(2) | Use of All-source Intelligence | SP800-53-enhancement |
| nist-800-53:RA-3(3) | Dynamic Threat Awareness | SP800-53-enhancement |
| nist-800-53:RA-3(4) | Predictive Cyber Analytics | SP800-53-enhancement |
| nist-800-53:RA-4 | Risk Assessment Update | SP800-53 (deprecated) |
| nist-800-53:RA-5 | Vulnerability Monitoring and Scanning | SP800-53 |
| nist-800-53:RA-5(1) | Update Tool Capability | SP800-53-enhancement (deprecated) |
| nist-800-53:RA-5(10) | Correlate Scanning Information | SP800-53-enhancement |
| nist-800-53:RA-5(11) | Public Disclosure Program | SP800-53-enhancement |
| nist-800-53:RA-5(2) | Update Vulnerabilities to Be Scanned | SP800-53-enhancement |
| nist-800-53:RA-5(3) | Breadth and Depth of Coverage | SP800-53-enhancement |
| nist-800-53:RA-5(4) | Discoverable Information | SP800-53-enhancement |
| nist-800-53:RA-5(5) | Privileged Access | SP800-53-enhancement |
| nist-800-53:RA-5(6) | Automated Trend Analyses | SP800-53-enhancement |
| nist-800-53:RA-5(7) | Automated Detection and Notification of Unauthorized Components | SP800-53-enhancement (deprecated) |
| nist-800-53:RA-5(8) | Review Historic Audit Logs | SP800-53-enhancement |
| nist-800-53:RA-5(9) | Penetration Testing and Analyses | SP800-53-enhancement (deprecated) |
| nist-800-53:RA-6 | Technical Surveillance Countermeasures Survey | SP800-53 |
| nist-800-53:RA-7 | Risk Response | SP800-53 |
| nist-800-53:RA-8 | Privacy Impact Assessments | SP800-53 |
| nist-800-53:RA-9 | Criticality Analysis | SP800-53 |
| nist-800-53:SA | System and Services Acquisition | family |
| nist-800-53:SA-1 | Policy and Procedures | SP800-53 |
| nist-800-53:SA-10 | Developer Configuration Management | SP800-53 |
| nist-800-53:SA-10(1) | Software and Firmware Integrity Verification | SP800-53-enhancement |
| nist-800-53:SA-10(2) | Alternative Configuration Management Processes | SP800-53-enhancement |
| nist-800-53:SA-10(3) | Hardware Integrity Verification | SP800-53-enhancement |
| nist-800-53:SA-10(4) | Trusted Generation | SP800-53-enhancement |
| nist-800-53:SA-10(5) | Mapping Integrity for Version Control | SP800-53-enhancement |
| nist-800-53:SA-10(6) | Trusted Distribution | SP800-53-enhancement |
| nist-800-53:SA-10(7) | Security and Privacy Representatives | SP800-53-enhancement |
| nist-800-53:SA-11 | Developer Testing and Evaluation | SP800-53 |
| nist-800-53:SA-11(1) | Static Code Analysis | SP800-53-enhancement |
| nist-800-53:SA-11(2) | Threat Modeling and Vulnerability Analyses | SP800-53-enhancement |
| nist-800-53:SA-11(3) | Independent Verification of Assessment Plans and Evidence | SP800-53-enhancement |
| nist-800-53:SA-11(4) | Manual Code Reviews | SP800-53-enhancement |
| nist-800-53:SA-11(5) | Penetration Testing | SP800-53-enhancement |
| nist-800-53:SA-11(6) | Attack Surface Reviews | SP800-53-enhancement |
| nist-800-53:SA-11(7) | Verify Scope of Testing and Evaluation | SP800-53-enhancement |
| nist-800-53:SA-11(8) | Dynamic Code Analysis | SP800-53-enhancement |
| nist-800-53:SA-11(9) | Interactive Application Security Testing | SP800-53-enhancement |
| nist-800-53:SA-12 | Supply Chain Protection | SP800-53 (deprecated) |
| nist-800-53:SA-12(1) | Acquisition Strategies / Tools / Methods | SP800-53-enhancement (deprecated) |
| nist-800-53:SA-12(10) | Validate as Genuine and Not Altered | SP800-53-enhancement (deprecated) |
| nist-800-53:SA-12(11) | Penetration Testing / Analysis of Elements, Processes, and Actors | SP800-53-enhancement (deprecated) |
| nist-800-53:SA-12(12) | Inter-organizational Agreements | SP800-53-enhancement (deprecated) |
| nist-800-53:SA-12(13) | Critical Information System Components | SP800-53-enhancement (deprecated) |
| nist-800-53:SA-12(14) | Identity and Traceability | SP800-53-enhancement (deprecated) |
| nist-800-53:SA-12(15) | Processes to Address Weaknesses or Deficiencies | SP800-53-enhancement (deprecated) |
| nist-800-53:SA-12(2) | Supplier Reviews | SP800-53-enhancement (deprecated) |
| nist-800-53:SA-12(3) | Trusted Shipping and Warehousing | SP800-53-enhancement (deprecated) |
| nist-800-53:SA-12(4) | Diversity of Suppliers | SP800-53-enhancement (deprecated) |
| nist-800-53:SA-12(5) | Limitation of Harm | SP800-53-enhancement (deprecated) |
| nist-800-53:SA-12(6) | Minimizing Procurement Time | SP800-53-enhancement (deprecated) |
| nist-800-53:SA-12(7) | Assessments Prior to Selection / Acceptance / Update | SP800-53-enhancement (deprecated) |
| nist-800-53:SA-12(8) | Use of All-source Intelligence | SP800-53-enhancement (deprecated) |
| nist-800-53:SA-12(9) | Operations Security | SP800-53-enhancement (deprecated) |
| nist-800-53:SA-13 | Trustworthiness | SP800-53 (deprecated) |
| nist-800-53:SA-14 | Criticality Analysis | SP800-53 (deprecated) |
| nist-800-53:SA-14(1) | Critical Components with No Viable Alternative Sourcing | SP800-53-enhancement (deprecated) |
| nist-800-53:SA-15 | Development Process, Standards, and Tools | SP800-53 |
| nist-800-53:SA-15(1) | Quality Metrics | SP800-53-enhancement |
| nist-800-53:SA-15(10) | Incident Response Plan | SP800-53-enhancement |
| nist-800-53:SA-15(11) | Archive System or Component | SP800-53-enhancement |
| nist-800-53:SA-15(12) | Minimize Personally Identifiable Information | SP800-53-enhancement |
| nist-800-53:SA-15(13) | Logging Syntax | SP800-53-enhancement |
| nist-800-53:SA-15(2) | Security and Privacy Tracking Tools | SP800-53-enhancement |
| nist-800-53:SA-15(3) | Criticality Analysis | SP800-53-enhancement |
| nist-800-53:SA-15(4) | Threat Modeling and Vulnerability Analysis | SP800-53-enhancement (deprecated) |
| nist-800-53:SA-15(5) | Attack Surface Reduction | SP800-53-enhancement |
| nist-800-53:SA-15(6) | Continuous Improvement | SP800-53-enhancement |
| nist-800-53:SA-15(7) | Automated Vulnerability Analysis | SP800-53-enhancement |
| nist-800-53:SA-15(8) | Reuse of Threat and Vulnerability Information | SP800-53-enhancement |
| nist-800-53:SA-15(9) | Use of Live Data | SP800-53-enhancement (deprecated) |
| nist-800-53:SA-16 | Developer-provided Training | SP800-53 |
| nist-800-53:SA-17 | Developer Security and Privacy Architecture and Design | SP800-53 |
| nist-800-53:SA-17(1) | Formal Policy Model | SP800-53-enhancement |
| nist-800-53:SA-17(2) | Security-relevant Components | SP800-53-enhancement |
| nist-800-53:SA-17(3) | Formal Correspondence | SP800-53-enhancement |
| nist-800-53:SA-17(4) | Informal Correspondence | SP800-53-enhancement |
| nist-800-53:SA-17(5) | Conceptually Simple Design | SP800-53-enhancement |
| nist-800-53:SA-17(6) | Structure for Testing | SP800-53-enhancement |
| nist-800-53:SA-17(7) | Structure for Least Privilege | SP800-53-enhancement |
| nist-800-53:SA-17(8) | Orchestration | SP800-53-enhancement |
| nist-800-53:SA-17(9) | Design Diversity | SP800-53-enhancement |
| nist-800-53:SA-18 | Tamper Resistance and Detection | SP800-53 (deprecated) |
| nist-800-53:SA-18(1) | Multiple Phases of System Development Life Cycle | SP800-53-enhancement (deprecated) |
| nist-800-53:SA-18(2) | Inspection of Systems or Components | SP800-53-enhancement (deprecated) |
| nist-800-53:SA-19 | Component Authenticity | SP800-53 (deprecated) |
| nist-800-53:SA-19(1) | Anti-counterfeit Training | SP800-53-enhancement (deprecated) |
| nist-800-53:SA-19(2) | Configuration Control for Component Service and Repair | SP800-53-enhancement (deprecated) |
| nist-800-53:SA-19(3) | Component Disposal | SP800-53-enhancement (deprecated) |
| nist-800-53:SA-19(4) | Anti-counterfeit Scanning | SP800-53-enhancement (deprecated) |
| nist-800-53:SA-2 | Allocation of Resources | SP800-53 |
| nist-800-53:SA-20 | Customized Development of Critical Components | SP800-53 |
| nist-800-53:SA-21 | Developer Screening | SP800-53 |
| nist-800-53:SA-21(1) | Validation of Screening | SP800-53-enhancement (deprecated) |
| nist-800-53:SA-22 | Unsupported System Components | SP800-53 |
| nist-800-53:SA-22(1) | Alternative Sources for Continued Support | SP800-53-enhancement (deprecated) |
| nist-800-53:SA-23 | Specialization | SP800-53 |
| nist-800-53:SA-24 | Design For Cyber Resiliency | SP800-53 |
| nist-800-53:SA-3 | System Development Life Cycle | SP800-53 |
| nist-800-53:SA-3(1) | Manage Preproduction Environment | SP800-53-enhancement |
| nist-800-53:SA-3(2) | Use of Live or Operational Data | SP800-53-enhancement |
| nist-800-53:SA-3(3) | Technology Refresh | SP800-53-enhancement |
| nist-800-53:SA-4 | Acquisition Process | SP800-53 |
| nist-800-53:SA-4(1) | Functional Properties of Controls | SP800-53-enhancement |
| nist-800-53:SA-4(10) | Use of Approved PIV Products | SP800-53-enhancement |
| nist-800-53:SA-4(11) | System of Records | SP800-53-enhancement |
| nist-800-53:SA-4(12) | Data Ownership | SP800-53-enhancement |
| nist-800-53:SA-4(2) | Design and Implementation Information for Controls | SP800-53-enhancement |
| nist-800-53:SA-4(3) | Development Methods, Techniques, and Practices | SP800-53-enhancement |
| nist-800-53:SA-4(4) | Assignment of Components to Systems | SP800-53-enhancement (deprecated) |
| nist-800-53:SA-4(5) | System, Component, and Service Configurations | SP800-53-enhancement |
| nist-800-53:SA-4(6) | Use of Information Assurance Products | SP800-53-enhancement |
| nist-800-53:SA-4(7) | NIAP-approved Protection Profiles  | SP800-53-enhancement |
| nist-800-53:SA-4(8) | Continuous Monitoring Plan for Controls | SP800-53-enhancement |
| nist-800-53:SA-4(9) | Functions, Ports, Protocols, and Services in Use | SP800-53-enhancement |
| nist-800-53:SA-5 | System Documentation | SP800-53 |
| nist-800-53:SA-5(1) | Functional Properties of Security Controls | SP800-53-enhancement (deprecated) |
| nist-800-53:SA-5(2) | Security-relevant External System Interfaces | SP800-53-enhancement (deprecated) |
| nist-800-53:SA-5(3) | High-level Design | SP800-53-enhancement (deprecated) |
| nist-800-53:SA-5(4) | Low-level Design | SP800-53-enhancement (deprecated) |
| nist-800-53:SA-5(5) | Source Code | SP800-53-enhancement (deprecated) |
| nist-800-53:SA-6 | Software Usage Restrictions | SP800-53 (deprecated) |
| nist-800-53:SA-7 | User-installed Software | SP800-53 (deprecated) |
| nist-800-53:SA-8 | Security and Privacy Engineering Principles | SP800-53 |
| nist-800-53:SA-8(1) | Clear Abstractions | SP800-53-enhancement |
| nist-800-53:SA-8(10) | Hierarchical Trust | SP800-53-enhancement |
| nist-800-53:SA-8(11) | Inverse Modification Threshold | SP800-53-enhancement |
| nist-800-53:SA-8(12) | Hierarchical Protection | SP800-53-enhancement |
| nist-800-53:SA-8(13) | Minimized Security Elements | SP800-53-enhancement |
| nist-800-53:SA-8(14) | Least Privilege | SP800-53-enhancement |
| nist-800-53:SA-8(15) | Predicate Permission | SP800-53-enhancement |
| nist-800-53:SA-8(16) | Self-reliant Trustworthiness | SP800-53-enhancement |
| nist-800-53:SA-8(17) | Secure Distributed Composition | SP800-53-enhancement |
| nist-800-53:SA-8(18) | Trusted Communications Channels | SP800-53-enhancement |
| nist-800-53:SA-8(19) | Continuous Protection | SP800-53-enhancement |
| nist-800-53:SA-8(2) | Least Common Mechanism | SP800-53-enhancement |
| nist-800-53:SA-8(20) | Secure Metadata Management | SP800-53-enhancement |
| nist-800-53:SA-8(21) | Self-analysis | SP800-53-enhancement |
| nist-800-53:SA-8(22) | Accountability and Traceability | SP800-53-enhancement |
| nist-800-53:SA-8(23) | Secure Defaults | SP800-53-enhancement |
| nist-800-53:SA-8(24) | Secure Failure and Recovery | SP800-53-enhancement |
| nist-800-53:SA-8(25) | Economic Security | SP800-53-enhancement |
| nist-800-53:SA-8(26) | Performance Security | SP800-53-enhancement |
| nist-800-53:SA-8(27) | Human Factored Security | SP800-53-enhancement |
| nist-800-53:SA-8(28) | Acceptable Security | SP800-53-enhancement |
| nist-800-53:SA-8(29) | Repeatable and Documented Procedures | SP800-53-enhancement |
| nist-800-53:SA-8(3) | Modularity and Layering | SP800-53-enhancement |
| nist-800-53:SA-8(30) | Procedural Rigor | SP800-53-enhancement |
| nist-800-53:SA-8(31) | Secure System Modification | SP800-53-enhancement |
| nist-800-53:SA-8(32) | Sufficient Documentation | SP800-53-enhancement |
| nist-800-53:SA-8(33) | Minimization | SP800-53-enhancement |
| nist-800-53:SA-8(4) | Partially Ordered Dependencies | SP800-53-enhancement |
| nist-800-53:SA-8(5) | Efficiently Mediated Access | SP800-53-enhancement |
| nist-800-53:SA-8(6) | Minimized Sharing | SP800-53-enhancement |
| nist-800-53:SA-8(7) | Reduced Complexity | SP800-53-enhancement |
| nist-800-53:SA-8(8) | Secure Evolvability | SP800-53-enhancement |
| nist-800-53:SA-8(9) | Trusted Components | SP800-53-enhancement |
| nist-800-53:SA-9 | External System Services | SP800-53 |
| nist-800-53:SA-9(1) | Risk Assessments and Organizational Approvals | SP800-53-enhancement |
| nist-800-53:SA-9(2) | Identification of Functions, Ports, Protocols, and Services | SP800-53-enhancement |
| nist-800-53:SA-9(3) | Establish and Maintain Trust Relationship with Providers | SP800-53-enhancement |
| nist-800-53:SA-9(4) | Consistent Interests of Consumers and Providers | SP800-53-enhancement |
| nist-800-53:SA-9(5) | Processing, Storage, and Service Location | SP800-53-enhancement |
| nist-800-53:SA-9(6) | Organization-controlled Cryptographic Keys | SP800-53-enhancement |
| nist-800-53:SA-9(7) | Organization-controlled Integrity Checking | SP800-53-enhancement |
| nist-800-53:SA-9(8) | Processing and Storage Location — U.S. Jurisdiction | SP800-53-enhancement |
| nist-800-53:SC | System and Communications Protection | family |
| nist-800-53:SC-1 | Policy and Procedures | SP800-53 |
| nist-800-53:SC-10 | Network Disconnect | SP800-53 |
| nist-800-53:SC-11 | Trusted Path | SP800-53 |
| nist-800-53:SC-11(1) | Irrefutable Communications Path | SP800-53-enhancement |
| nist-800-53:SC-12 | Cryptographic Key Establishment and Management | SP800-53 |
| nist-800-53:SC-12(1) | Availability | SP800-53-enhancement |
| nist-800-53:SC-12(2) | Symmetric Keys | SP800-53-enhancement |
| nist-800-53:SC-12(3) | Asymmetric Keys | SP800-53-enhancement |
| nist-800-53:SC-12(4) | PKI Certificates | SP800-53-enhancement (deprecated) |
| nist-800-53:SC-12(5) | PKI Certificates / Hardware Tokens | SP800-53-enhancement (deprecated) |
| nist-800-53:SC-12(6) | Physical Control of Keys | SP800-53-enhancement |
| nist-800-53:SC-13 | Cryptographic Protection | SP800-53 |
| nist-800-53:SC-13(1) | FIPS-validated Cryptography | SP800-53-enhancement (deprecated) |
| nist-800-53:SC-13(2) | NSA-approved Cryptography | SP800-53-enhancement (deprecated) |
| nist-800-53:SC-13(3) | Individuals Without Formal Access Approvals | SP800-53-enhancement (deprecated) |
| nist-800-53:SC-13(4) | Digital Signatures | SP800-53-enhancement (deprecated) |
| nist-800-53:SC-14 | Public Access Protections | SP800-53 (deprecated) |
| nist-800-53:SC-15 | Collaborative Computing Devices and Applications | SP800-53 |
| nist-800-53:SC-15(1) | Physical or Logical Disconnect | SP800-53-enhancement |
| nist-800-53:SC-15(2) | Blocking Inbound and Outbound Communications Traffic | SP800-53-enhancement (deprecated) |
| nist-800-53:SC-15(3) | Disabling and Removal in Secure Work Areas | SP800-53-enhancement |
| nist-800-53:SC-15(4) | Explicitly Indicate Current Participants | SP800-53-enhancement |
| nist-800-53:SC-16 | Transmission of Security and Privacy Attributes | SP800-53 |
| nist-800-53:SC-16(1) | Integrity Verification | SP800-53-enhancement |
| nist-800-53:SC-16(2) | Anti-spoofing Mechanisms | SP800-53-enhancement |
| nist-800-53:SC-16(3) | Cryptographic Binding | SP800-53-enhancement |
| nist-800-53:SC-17 | Public Key Infrastructure Certificates | SP800-53 |
| nist-800-53:SC-18 | Mobile Code | SP800-53 |
| nist-800-53:SC-18(1) | Identify Unacceptable Code and Take Corrective Actions | SP800-53-enhancement |
| nist-800-53:SC-18(2) | Acquisition, Development, and Use | SP800-53-enhancement |
| nist-800-53:SC-18(3) | Prevent Downloading and Execution | SP800-53-enhancement |
| nist-800-53:SC-18(4) | Prevent Automatic Execution | SP800-53-enhancement |
| nist-800-53:SC-18(5) | Allow Execution Only in Confined Environments | SP800-53-enhancement |
| nist-800-53:SC-19 | Voice Over Internet Protocol | SP800-53 (deprecated) |
| nist-800-53:SC-2 | Separation of System and User Functionality | SP800-53 |
| nist-800-53:SC-2(1) | Interfaces for Non-privileged Users | SP800-53-enhancement |
| nist-800-53:SC-2(2) | Disassociability | SP800-53-enhancement |
| nist-800-53:SC-20 | Secure Name/Address Resolution Service (Authoritative Source) | SP800-53 |
| nist-800-53:SC-20(1) | Child Subspaces | SP800-53-enhancement (deprecated) |
| nist-800-53:SC-20(2) | Data Origin and Integrity | SP800-53-enhancement |
| nist-800-53:SC-21 | Secure Name/Address Resolution Service (Recursive or Caching Resolver) | SP800-53 |
| nist-800-53:SC-21(1) | Data Origin and Integrity | SP800-53-enhancement (deprecated) |
| nist-800-53:SC-22 | Architecture and Provisioning for Name/Address Resolution Service | SP800-53 |
| nist-800-53:SC-23 | Session Authenticity | SP800-53 |
| nist-800-53:SC-23(1) | Invalidate Session Identifiers at Logout | SP800-53-enhancement |
| nist-800-53:SC-23(2) | User-initiated Logouts and Message Displays | SP800-53-enhancement (deprecated) |
| nist-800-53:SC-23(3) | Unique System-generated Session Identifiers | SP800-53-enhancement |
| nist-800-53:SC-23(4) | Unique Session Identifiers with Randomization | SP800-53-enhancement (deprecated) |
| nist-800-53:SC-23(5) | Allowed Certificate Authorities | SP800-53-enhancement |
| nist-800-53:SC-24 | Fail in Known State | SP800-53 |
| nist-800-53:SC-25 | Thin Nodes | SP800-53 |
| nist-800-53:SC-26 | Decoys | SP800-53 |
| nist-800-53:SC-26(1) | Detection of Malicious Code | SP800-53-enhancement (deprecated) |
| nist-800-53:SC-27 | Platform-independent Applications | SP800-53 |
| nist-800-53:SC-28 | Protection of Information at Rest | SP800-53 |
| nist-800-53:SC-28(1) | Cryptographic Protection | SP800-53-enhancement |
| nist-800-53:SC-28(2) | Offline Storage | SP800-53-enhancement |
| nist-800-53:SC-28(3) | Cryptographic Keys | SP800-53-enhancement |
| nist-800-53:SC-29 | Heterogeneity | SP800-53 |
| nist-800-53:SC-29(1) | Virtualization Techniques | SP800-53-enhancement |
| nist-800-53:SC-3 | Security Function Isolation | SP800-53 |
| nist-800-53:SC-3(1) | Hardware Separation | SP800-53-enhancement |
| nist-800-53:SC-3(2) | Access and Flow Control Functions | SP800-53-enhancement |
| nist-800-53:SC-3(3) | Minimize Nonsecurity Functionality | SP800-53-enhancement |
| nist-800-53:SC-3(4) | Module Coupling and Cohesiveness | SP800-53-enhancement |
| nist-800-53:SC-3(5) | Layered Structures | SP800-53-enhancement |
| nist-800-53:SC-30 | Concealment and Misdirection | SP800-53 |
| nist-800-53:SC-30(1) | Virtualization Techniques | SP800-53-enhancement (deprecated) |
| nist-800-53:SC-30(2) | Randomness | SP800-53-enhancement |
| nist-800-53:SC-30(3) | Change Processing and Storage Locations | SP800-53-enhancement |
| nist-800-53:SC-30(4) | Misleading Information | SP800-53-enhancement |
| nist-800-53:SC-30(5) | Concealment of System Components | SP800-53-enhancement |
| nist-800-53:SC-31 | Covert Channel Analysis | SP800-53 |
| nist-800-53:SC-31(1) | Test Covert Channels for Exploitability | SP800-53-enhancement |
| nist-800-53:SC-31(2) | Maximum Bandwidth | SP800-53-enhancement |
| nist-800-53:SC-31(3) | Measure Bandwidth in Operational Environments | SP800-53-enhancement |
| nist-800-53:SC-32 | System Partitioning | SP800-53 |
| nist-800-53:SC-32(1) | Separate Physical Domains for Privileged Functions | SP800-53-enhancement |
| nist-800-53:SC-33 | Transmission Preparation Integrity | SP800-53 (deprecated) |
| nist-800-53:SC-34 | Non-modifiable Executable Programs | SP800-53 |
| nist-800-53:SC-34(1) | No Writable Storage | SP800-53-enhancement |
| nist-800-53:SC-34(2) | Integrity Protection on Read-only Media | SP800-53-enhancement |
| nist-800-53:SC-34(3) | Hardware-based Protection | SP800-53-enhancement (deprecated) |
| nist-800-53:SC-35 | External Malicious Code Identification | SP800-53 |
| nist-800-53:SC-36 | Distributed Processing and Storage | SP800-53 |
| nist-800-53:SC-36(1) | Polling Techniques | SP800-53-enhancement |
| nist-800-53:SC-36(2) | Synchronization | SP800-53-enhancement |
| nist-800-53:SC-37 | Out-of-band Channels | SP800-53 |
| nist-800-53:SC-37(1) | Ensure Delivery and Transmission | SP800-53-enhancement |
| nist-800-53:SC-38 | Operations Security | SP800-53 |
| nist-800-53:SC-39 | Process Isolation | SP800-53 |
| nist-800-53:SC-39(1) | Hardware Separation | SP800-53-enhancement |
| nist-800-53:SC-39(2) | Separate Execution Domain Per Thread | SP800-53-enhancement |
| nist-800-53:SC-4 | Information in Shared System Resources | SP800-53 |
| nist-800-53:SC-4(1) | Security Levels | SP800-53-enhancement (deprecated) |
| nist-800-53:SC-4(2) | Multilevel or Periods Processing | SP800-53-enhancement |
| nist-800-53:SC-40 | Wireless Link Protection | SP800-53 |
| nist-800-53:SC-40(1) | Electromagnetic Interference | SP800-53-enhancement |
| nist-800-53:SC-40(2) | Reduce Detection Potential | SP800-53-enhancement |
| nist-800-53:SC-40(3) | Imitative or Manipulative Communications Deception | SP800-53-enhancement |
| nist-800-53:SC-40(4) | Signal Parameter Identification | SP800-53-enhancement |
| nist-800-53:SC-41 | Port and I/O Device Access | SP800-53 |
| nist-800-53:SC-42 | Sensor Capability and Data | SP800-53 |
| nist-800-53:SC-42(1) | Reporting to Authorized Individuals or Roles | SP800-53-enhancement |
| nist-800-53:SC-42(2) | Authorized Use | SP800-53-enhancement |
| nist-800-53:SC-42(3) | Prohibit Use of Devices | SP800-53-enhancement (deprecated) |
| nist-800-53:SC-42(4) | Notice of Collection | SP800-53-enhancement |
| nist-800-53:SC-42(5) | Collection Minimization | SP800-53-enhancement |
| nist-800-53:SC-43 | Usage Restrictions | SP800-53 |
| nist-800-53:SC-44 | Detonation Chambers | SP800-53 |
| nist-800-53:SC-45 | System Time Synchronization | SP800-53 |
| nist-800-53:SC-45(1) | Synchronization with Authoritative Time Source | SP800-53-enhancement |
| nist-800-53:SC-45(2) | Secondary Authoritative Time Source | SP800-53-enhancement |
| nist-800-53:SC-46 | Cross Domain Policy Enforcement | SP800-53 |
| nist-800-53:SC-47 | Alternate Communications Paths | SP800-53 |
| nist-800-53:SC-48 | Sensor Relocation | SP800-53 |
| nist-800-53:SC-48(1) | Dynamic Relocation of Sensors or Monitoring Capabilities | SP800-53-enhancement |
| nist-800-53:SC-49 | Hardware-enforced Separation and Policy Enforcement | SP800-53 |
| nist-800-53:SC-5 | Denial-of-service Protection | SP800-53 |
| nist-800-53:SC-5(1) | Restrict Ability to Attack Other Systems | SP800-53-enhancement |
| nist-800-53:SC-5(2) | Capacity, Bandwidth, and Redundancy | SP800-53-enhancement |
| nist-800-53:SC-5(3) | Detection and Monitoring | SP800-53-enhancement |
| nist-800-53:SC-50 | Software-enforced Separation and Policy Enforcement | SP800-53 |
| nist-800-53:SC-51 | Hardware-based Protection | SP800-53 |
| nist-800-53:SC-6 | Resource Availability | SP800-53 |
| nist-800-53:SC-7 | Boundary Protection | SP800-53 |
| nist-800-53:SC-7(1) | Physically Separated Subnetworks | SP800-53-enhancement (deprecated) |
| nist-800-53:SC-7(10) | Prevent Exfiltration | SP800-53-enhancement |
| nist-800-53:SC-7(11) | Restrict Incoming Communications Traffic | SP800-53-enhancement |
| nist-800-53:SC-7(12) | Host-based Protection | SP800-53-enhancement |
| nist-800-53:SC-7(13) | Isolation of Security Tools, Mechanisms, and Support Components | SP800-53-enhancement |
| nist-800-53:SC-7(14) | Protect Against Unauthorized Physical Connections | SP800-53-enhancement |
| nist-800-53:SC-7(15) | Networked Privileged Accesses | SP800-53-enhancement |
| nist-800-53:SC-7(16) | Prevent Discovery of System Components | SP800-53-enhancement |
| nist-800-53:SC-7(17) | Automated Enforcement of Protocol Formats | SP800-53-enhancement |
| nist-800-53:SC-7(18) | Fail Secure | SP800-53-enhancement |
| nist-800-53:SC-7(19) | Block Communication from Non-organizationally Configured Hosts | SP800-53-enhancement |
| nist-800-53:SC-7(2) | Public Access | SP800-53-enhancement (deprecated) |
| nist-800-53:SC-7(20) | Dynamic Isolation and Segregation | SP800-53-enhancement |
| nist-800-53:SC-7(21) | Isolation of System Components | SP800-53-enhancement |
| nist-800-53:SC-7(22) | Separate Subnets for Connecting to Different Security Domains | SP800-53-enhancement |
| nist-800-53:SC-7(23) | Disable Sender Feedback on Protocol Validation Failure | SP800-53-enhancement |
| nist-800-53:SC-7(24) | Personally Identifiable Information | SP800-53-enhancement |
| nist-800-53:SC-7(25) | Unclassified National Security System Connections | SP800-53-enhancement |
| nist-800-53:SC-7(26) | Classified National Security System Connections | SP800-53-enhancement |
| nist-800-53:SC-7(27) | Unclassified Non-national Security System Connections | SP800-53-enhancement |
| nist-800-53:SC-7(28) | Connections to Public Networks | SP800-53-enhancement |
| nist-800-53:SC-7(29) | Separate Subnets to Isolate Functions | SP800-53-enhancement |
| nist-800-53:SC-7(3) | Access Points | SP800-53-enhancement |
| nist-800-53:SC-7(4) | External Telecommunications Services | SP800-53-enhancement |
| nist-800-53:SC-7(5) | Deny by Default — Allow by Exception | SP800-53-enhancement |
| nist-800-53:SC-7(6) | Response to Recognized Failures | SP800-53-enhancement (deprecated) |
| nist-800-53:SC-7(7) | Split Tunneling for Remote Devices | SP800-53-enhancement |
| nist-800-53:SC-7(8) | Route Traffic to Authenticated Proxy Servers | SP800-53-enhancement |
| nist-800-53:SC-7(9) | Restrict Threatening Outgoing Communications Traffic | SP800-53-enhancement |
| nist-800-53:SC-8 | Transmission Confidentiality and Integrity | SP800-53 |
| nist-800-53:SC-8(1) | Cryptographic Protection | SP800-53-enhancement |
| nist-800-53:SC-8(2) | Pre- and Post-transmission Handling | SP800-53-enhancement |
| nist-800-53:SC-8(3) | Cryptographic Protection for Message Externals | SP800-53-enhancement |
| nist-800-53:SC-8(4) | Conceal or Randomize Communications | SP800-53-enhancement |
| nist-800-53:SC-8(5) | Protected Distribution System | SP800-53-enhancement |
| nist-800-53:SC-9 | Transmission Confidentiality | SP800-53 (deprecated) |
| nist-800-53:SI | System and Information Integrity | family |
| nist-800-53:SI-1 | Policy and Procedures | SP800-53 |
| nist-800-53:SI-10 | Information Input Validation | SP800-53 |
| nist-800-53:SI-10(1) | Manual Override Capability | SP800-53-enhancement |
| nist-800-53:SI-10(2) | Review and Resolve Errors | SP800-53-enhancement |
| nist-800-53:SI-10(3) | Predictable Behavior | SP800-53-enhancement |
| nist-800-53:SI-10(4) | Timing Interactions | SP800-53-enhancement |
| nist-800-53:SI-10(5) | Restrict Inputs to Trusted Sources and Approved Formats | SP800-53-enhancement |
| nist-800-53:SI-10(6) | Injection Prevention | SP800-53-enhancement |
| nist-800-53:SI-11 | Error Handling | SP800-53 |
| nist-800-53:SI-12 | Information Management and Retention | SP800-53 |
| nist-800-53:SI-12(1) | Limit Personally Identifiable Information Elements | SP800-53-enhancement |
| nist-800-53:SI-12(2) | Minimize Personally Identifiable Information in Testing, Training, and Research | SP800-53-enhancement |
| nist-800-53:SI-12(3) | Information Disposal | SP800-53-enhancement |
| nist-800-53:SI-13 | Predictable Failure Prevention | SP800-53 |
| nist-800-53:SI-13(1) | Transferring Component Responsibilities | SP800-53-enhancement |
| nist-800-53:SI-13(2) | Time Limit on Process Execution Without Supervision | SP800-53-enhancement (deprecated) |
| nist-800-53:SI-13(3) | Manual Transfer Between Components | SP800-53-enhancement |
| nist-800-53:SI-13(4) | Standby Component Installation and Notification | SP800-53-enhancement |
| nist-800-53:SI-13(5) | Failover Capability | SP800-53-enhancement |
| nist-800-53:SI-14 | Non-persistence | SP800-53 |
| nist-800-53:SI-14(1) | Refresh from Trusted Sources | SP800-53-enhancement |
| nist-800-53:SI-14(2) | Non-persistent Information | SP800-53-enhancement |
| nist-800-53:SI-14(3) | Non-persistent Connectivity | SP800-53-enhancement |
| nist-800-53:SI-15 | Information Output Filtering | SP800-53 |
| nist-800-53:SI-16 | Memory Protection | SP800-53 |
| nist-800-53:SI-17 | Fail-safe Procedures | SP800-53 |
| nist-800-53:SI-18 | Personally Identifiable Information Quality Operations | SP800-53 |
| nist-800-53:SI-18(1) | Automation Support | SP800-53-enhancement |
| nist-800-53:SI-18(2) | Data Tags | SP800-53-enhancement |
| nist-800-53:SI-18(3) | Collection | SP800-53-enhancement |
| nist-800-53:SI-18(4) | Individual Requests | SP800-53-enhancement |
| nist-800-53:SI-18(5) | Notice of Correction or Deletion | SP800-53-enhancement |
| nist-800-53:SI-19 | De-identification | SP800-53 |
| nist-800-53:SI-19(1) | Collection | SP800-53-enhancement |
| nist-800-53:SI-19(2) | Archiving | SP800-53-enhancement |
| nist-800-53:SI-19(3) | Release | SP800-53-enhancement |
| nist-800-53:SI-19(4) | Removal, Masking, Encryption, Hashing, or Replacement of Direct Identifiers | SP800-53-enhancement |
| nist-800-53:SI-19(5) | Statistical Disclosure Control | SP800-53-enhancement |
| nist-800-53:SI-19(6) | Differential Privacy | SP800-53-enhancement |
| nist-800-53:SI-19(7) | Validated Algorithms and Software | SP800-53-enhancement |
| nist-800-53:SI-19(8) | Motivated Intruder | SP800-53-enhancement |
| nist-800-53:SI-2 | Flaw Remediation | SP800-53 |
| nist-800-53:SI-2(1) | Central Management | SP800-53-enhancement (deprecated) |
| nist-800-53:SI-2(2) | Automated Flaw Remediation Status | SP800-53-enhancement |
| nist-800-53:SI-2(3) | Time to Remediate Flaws and Benchmarks for Corrective Actions | SP800-53-enhancement |
| nist-800-53:SI-2(4) | Automated Patch Management Tools | SP800-53-enhancement |
| nist-800-53:SI-2(5) | Automatic Software and Firmware Updates | SP800-53-enhancement |
| nist-800-53:SI-2(6) | Removal of Previous Versions of Software and Firmware | SP800-53-enhancement |
| nist-800-53:SI-2(7) | Root Cause Analysis | SP800-53-enhancement |
| nist-800-53:SI-20 | Tainting | SP800-53 |
| nist-800-53:SI-21 | Information Refresh | SP800-53 |
| nist-800-53:SI-22 | Information Diversity | SP800-53 |
| nist-800-53:SI-23 | Information Fragmentation | SP800-53 |
| nist-800-53:SI-3 | Malicious Code Protection | SP800-53 |
| nist-800-53:SI-3(1) | Central Management | SP800-53-enhancement (deprecated) |
| nist-800-53:SI-3(10) | Malicious Code Analysis | SP800-53-enhancement |
| nist-800-53:SI-3(2) | Automatic Updates | SP800-53-enhancement (deprecated) |
| nist-800-53:SI-3(3) | Non-privileged Users | SP800-53-enhancement (deprecated) |
| nist-800-53:SI-3(4) | Updates Only by Privileged Users | SP800-53-enhancement |
| nist-800-53:SI-3(5) | Portable Storage Devices | SP800-53-enhancement (deprecated) |
| nist-800-53:SI-3(6) | Testing and Verification | SP800-53-enhancement |
| nist-800-53:SI-3(7) | Nonsignature-based Detection | SP800-53-enhancement (deprecated) |
| nist-800-53:SI-3(8) | Detect Unauthorized Commands | SP800-53-enhancement |
| nist-800-53:SI-3(9) | Authenticate Remote Commands | SP800-53-enhancement (deprecated) |
| nist-800-53:SI-4 | System Monitoring | SP800-53 |
| nist-800-53:SI-4(1) | System-wide Intrusion Detection System | SP800-53-enhancement |
| nist-800-53:SI-4(10) | Visibility of Encrypted Communications | SP800-53-enhancement |
| nist-800-53:SI-4(11) | Analyze Communications Traffic Anomalies | SP800-53-enhancement |
| nist-800-53:SI-4(12) | Automated Organization-generated Alerts | SP800-53-enhancement |
| nist-800-53:SI-4(13) | Analyze Traffic and Event Patterns | SP800-53-enhancement |
| nist-800-53:SI-4(14) | Wireless Intrusion Detection | SP800-53-enhancement |
| nist-800-53:SI-4(15) | Wireless to Wireline Communications | SP800-53-enhancement |
| nist-800-53:SI-4(16) | Correlate Monitoring Information | SP800-53-enhancement |
| nist-800-53:SI-4(17) | Integrated Situational Awareness | SP800-53-enhancement |
| nist-800-53:SI-4(18) | Analyze Traffic and Covert Exfiltration | SP800-53-enhancement |
| nist-800-53:SI-4(19) | Risk for Individuals | SP800-53-enhancement |
| nist-800-53:SI-4(2) | Automated Tools and Mechanisms for Real-time Analysis | SP800-53-enhancement |
| nist-800-53:SI-4(20) | Privileged Users | SP800-53-enhancement |
| nist-800-53:SI-4(21) | Probationary Periods | SP800-53-enhancement |
| nist-800-53:SI-4(22) | Unauthorized Network Services | SP800-53-enhancement |
| nist-800-53:SI-4(23) | Host-based Devices | SP800-53-enhancement |
| nist-800-53:SI-4(24) | Indicators of Compromise | SP800-53-enhancement |
| nist-800-53:SI-4(25) | Optimize Network Traffic Analysis | SP800-53-enhancement |
| nist-800-53:SI-4(3) | Automated Tool and Mechanism Integration | SP800-53-enhancement |
| nist-800-53:SI-4(4) | Inbound and Outbound Communications Traffic | SP800-53-enhancement |
| nist-800-53:SI-4(5) | System-generated Alerts | SP800-53-enhancement |
| nist-800-53:SI-4(6) | Restrict Non-privileged Users | SP800-53-enhancement (deprecated) |
| nist-800-53:SI-4(7) | Automated Response to Suspicious Events | SP800-53-enhancement |
| nist-800-53:SI-4(8) | Protection of Monitoring Information | SP800-53-enhancement (deprecated) |
| nist-800-53:SI-4(9) | Testing of Monitoring Tools and Mechanisms | SP800-53-enhancement |
| nist-800-53:SI-5 | Security Alerts, Advisories, and Directives | SP800-53 |
| nist-800-53:SI-5(1) | Automated Alerts and Advisories | SP800-53-enhancement |
| nist-800-53:SI-6 | Security and Privacy Function Verification | SP800-53 |
| nist-800-53:SI-6(1) | Notification of Failed Security Tests | SP800-53-enhancement (deprecated) |
| nist-800-53:SI-6(2) | Automation Support for Distributed Testing | SP800-53-enhancement |
| nist-800-53:SI-6(3) | Report Verification Results | SP800-53-enhancement |
| nist-800-53:SI-7 | Software, Firmware, and Information Integrity | SP800-53 |
| nist-800-53:SI-7(1) | Integrity Checks | SP800-53-enhancement |
| nist-800-53:SI-7(10) | Protection of Boot Firmware | SP800-53-enhancement |
| nist-800-53:SI-7(11) | Confined Environments with Limited Privileges | SP800-53-enhancement (deprecated) |
| nist-800-53:SI-7(12) | Integrity Verification | SP800-53-enhancement |
| nist-800-53:SI-7(13) | Code Execution in Protected Environments | SP800-53-enhancement (deprecated) |
| nist-800-53:SI-7(14) | Binary or Machine Executable Code | SP800-53-enhancement (deprecated) |
| nist-800-53:SI-7(15) | Code Authentication | SP800-53-enhancement |
| nist-800-53:SI-7(16) | Time Limit on Process Execution Without Supervision | SP800-53-enhancement |
| nist-800-53:SI-7(17) | Runtime Application Self-protection | SP800-53-enhancement |
| nist-800-53:SI-7(2) | Automated Notifications of Integrity Violations | SP800-53-enhancement |
| nist-800-53:SI-7(3) | Centrally Managed Integrity Tools | SP800-53-enhancement |
| nist-800-53:SI-7(4) | Tamper-evident Packaging | SP800-53-enhancement (deprecated) |
| nist-800-53:SI-7(5) | Automated Response to Integrity Violations | SP800-53-enhancement |
| nist-800-53:SI-7(6) | Cryptographic Protection | SP800-53-enhancement |
| nist-800-53:SI-7(7) | Integration of Detection and Response | SP800-53-enhancement |
| nist-800-53:SI-7(8) | Auditing Capability for Significant Events | SP800-53-enhancement |
| nist-800-53:SI-7(9) | Verify Boot Process | SP800-53-enhancement |
| nist-800-53:SI-8 | Spam Protection | SP800-53 |
| nist-800-53:SI-8(1) | Central Management | SP800-53-enhancement (deprecated) |
| nist-800-53:SI-8(2) | Automatic Updates | SP800-53-enhancement |
| nist-800-53:SI-8(3) | Continuous Learning Capability | SP800-53-enhancement |
| nist-800-53:SI-9 | Information Input Restrictions | SP800-53 (deprecated) |
| nist-800-53:SR | Supply Chain Risk Management | family |
| nist-800-53:SR-1 | Policy and Procedures | SP800-53 |
| nist-800-53:SR-10 | Inspection of Systems or Components | SP800-53 |
| nist-800-53:SR-11 | Component Authenticity | SP800-53 |
| nist-800-53:SR-11(1) | Anti-counterfeit Training | SP800-53-enhancement |
| nist-800-53:SR-11(2) | Configuration Control for Component Service and Repair | SP800-53-enhancement |
| nist-800-53:SR-11(3) | Anti-counterfeit Scanning | SP800-53-enhancement |
| nist-800-53:SR-12 | Component Disposal | SP800-53 |
| nist-800-53:SR-2 | Supply Chain Risk Management Plan | SP800-53 |
| nist-800-53:SR-2(1) | Establish SCRM Team | SP800-53-enhancement |
| nist-800-53:SR-3 | Supply Chain Controls and Processes | SP800-53 |
| nist-800-53:SR-3(1) | Diverse Supply Base | SP800-53-enhancement |
| nist-800-53:SR-3(2) | Limitation of Harm | SP800-53-enhancement |
| nist-800-53:SR-3(3) | Sub-tier Flow Down | SP800-53-enhancement |
| nist-800-53:SR-4 | Provenance | SP800-53 |
| nist-800-53:SR-4(1) | Identity | SP800-53-enhancement |
| nist-800-53:SR-4(2) | Track and Trace | SP800-53-enhancement |
| nist-800-53:SR-4(3) | Validate as Genuine and Not Altered | SP800-53-enhancement |
| nist-800-53:SR-4(4) | Supply Chain Integrity — Pedigree | SP800-53-enhancement |
| nist-800-53:SR-5 | Acquisition Strategies, Tools, and Methods | SP800-53 |
| nist-800-53:SR-5(1) | Adequate Supply | SP800-53-enhancement |
| nist-800-53:SR-5(2) | Assessments Prior to Selection, Acceptance, Modification, or Update | SP800-53-enhancement |
| nist-800-53:SR-6 | Supplier Assessments and Reviews | SP800-53 |
| nist-800-53:SR-6(1) | Testing and Analysis | SP800-53-enhancement |
| nist-800-53:SR-7 | Supply Chain Operations Security | SP800-53 |
| nist-800-53:SR-8 | Notification Agreements | SP800-53 |
| nist-800-53:SR-9 | Tamper Resistance and Detection | SP800-53 |
| nist-800-53:SR-9(1) | Multiple Stages of System Development Life Cycle | SP800-53-enhancement |

## NIST AI Risk Management Framework

| ID | Name | Kind |
| --- | --- | --- |
| nist-ai-rmf:GOVERN | A culture of risk management is cultivated and present. | function |
| nist-ai-rmf:GOVERN 1 | Policies, processes, procedures and practices across the organization related to the mapping, measuring and managing of AI risks are in place, transparent, and implemented effectiv | category |
| nist-ai-rmf:GOVERN 1.1 | Legal and regulatory requirements involving AI are understood, managed, and documented. | subcategory |
| nist-ai-rmf:GOVERN 1.2 | The characteristics of trustworthy AI are integrated into organizational policies, processes, and procedures. | subcategory |
| nist-ai-rmf:GOVERN 1.3 | Processes and procedures are in place to determine the needed level of risk management activities based on the organization's risk tolerance. | subcategory |
| nist-ai-rmf:GOVERN 1.4 | The risk management process and its outcomes are established through transparent policies, procedures, and other controls based on organizational risk priorities. | subcategory |
| nist-ai-rmf:GOVERN 1.5 | Ongoing monitoring and periodic review of the risk management process and its outcomes are planned, organizational roles and responsibilities are clearly defined, including determi | subcategory |
| nist-ai-rmf:GOVERN 1.6 | Mechanisms are in place to inventory AI systems and are resourced according to organizational risk priorities. | subcategory |
| nist-ai-rmf:GOVERN 1.7 | Processes and procedures are in place for decommissioning and phasing out of AI systems safely and in a manner that does not increase risks or decrease the organization’s trustwort | subcategory |
| nist-ai-rmf:GOVERN 2 | Accountability structures are in place so that the appropriate teams and individuals are empowered, responsible, and trained for mapping, measuring, and managing AI risks. | category |
| nist-ai-rmf:GOVERN 2.1 | Roles and responsibilities and lines of communication related to mapping, measuring, and managing AI risks are documented and are clear to individuals and teams throughout the orga | subcategory |
| nist-ai-rmf:GOVERN 2.2 | The organization’s personnel and partners receive AI risk management training to enable them to perform their duties and responsibilities consistent with related policies, procedur | subcategory |
| nist-ai-rmf:GOVERN 2.3 | Executive leadership of the organization takes responsibility for decisions about risks associated with AI system development and deployment. | subcategory |
| nist-ai-rmf:GOVERN 3 | Workforce diversity, equity, inclusion, and accessibility processes are prioritized in the mapping, measuring, and managing of AI risks throughout the lifecycle. | category |
| nist-ai-rmf:GOVERN 3.1 | Decision-makings related to mapping, measuring, and managing AI risks throughout the lifecycle is informed by a diverse team (e.g., diversity of demographics, disciplines, experien | subcategory |
| nist-ai-rmf:GOVERN 3.2 | Policies and procedures are in place to define and differentiate roles and responsibilities for human-AI configurations and oversight of AI systems. | subcategory |
| nist-ai-rmf:GOVERN 4 | Organizational teams are committed to a culture that considers and communicates AI risk. | category |
| nist-ai-rmf:GOVERN 4.1 | Organizational policies, and practices are in place to foster a critical thinking and safety-first mindset in the design, development, deployment, and uses of AI systems to minimiz | subcategory |
| nist-ai-rmf:GOVERN 4.2 | Organizational teams document the risks and potential impacts of the AI technology they design, develop, deploy, evaluate and use, and communicate about the impacts more broadly. | subcategory |
| nist-ai-rmf:GOVERN 4.3 | Organizational practices are in place to enable AI testing, identification of incidents, and information sharing. | subcategory |
| nist-ai-rmf:GOVERN 5 | Processes are in place for robust engagement with relevant AI actors. | category |
| nist-ai-rmf:GOVERN 5.1 | Organizational policies and practices are in place to collect, consider, prioritize, and integrate feedback from those external to the team that developed or deployed the AI system | subcategory |
| nist-ai-rmf:GOVERN 5.2 | Mechanisms are established to enable AI actors to regularly incorporate adjudicated feedback from relevant AI actors into system design and implementation. | subcategory |
| nist-ai-rmf:GOVERN 6 | Policies and procedures are in place to address AI risks and benefits arising from third-party software and data and other supply chain issues. | category |
| nist-ai-rmf:GOVERN 6.1 | Policies and procedures are in place that address AI risks associated with third-party entities, including risks of infringement of a third party's intellectual property or other r | subcategory |
| nist-ai-rmf:GOVERN 6.2 | Contingency processes are in place to handle failures or incidents in third-party data or AI systems deemed to be high-risk. | subcategory |
| nist-ai-rmf:MANAGE | Risks are prioritized and acted upon based on a projected impact. | function |
| nist-ai-rmf:MANAGE 1 | AI risks based on assessments and other analytical output from the Map and measure functions are prioritized, responded to, and managed. | category |
| nist-ai-rmf:MANAGE 1.1 | A determination is made as to whether the AI system achieves its intended purpose and stated objectives and whether its development or deployment should proceed. | subcategory |
| nist-ai-rmf:MANAGE 1.2 | Treatment of documented AI risks is prioritized based on impact, likelihood, or available resources or methods. | subcategory |
| nist-ai-rmf:MANAGE 1.3 | Responses to the AI risks deemed high priority as identified by the Map function, are developed, planned, and documented. Risk response options can include mitigating, transferring | subcategory |
| nist-ai-rmf:MANAGE 1.4 | Negative residual risks (defined as the sum of all unmitigated risks) to both downstream acquirers of AI systems and end users are documented. | subcategory |
| nist-ai-rmf:MANAGE 2 | Strategies to maximize AI benefits and minimize negative impacts are planned, prepared, implemented, and documented, and informed by input from relevant AI actors. | category |
| nist-ai-rmf:MANAGE 2.1 | Resources required to manage AI risks are taken into account, along with viable non-AI alternative systems, approaches, or methods – to reduce the magnitude or likelihood of potent | subcategory |
| nist-ai-rmf:MANAGE 2.2 | Mechanisms are in place and applied to sustain the value of deployed AI systems. | subcategory |
| nist-ai-rmf:MANAGE 2.3 | Procedures are followed to respond to and recover from a previously unknown risk when it is identified. | subcategory |
| nist-ai-rmf:MANAGE 2.4 | Mechanisms are in place and applied, responsibilities are assigned and understood to supersede, disengage, or deactivate AI systems that demonstrate performance or outcomes inconsi | subcategory |
| nist-ai-rmf:MANAGE 3 | AI risks and benefits from third-party entities are managed. | category |
| nist-ai-rmf:MANAGE 3.1 | AI risks and benefits from third-party resources are regularly monitored, and risk controls are applied and documented. | subcategory |
| nist-ai-rmf:MANAGE 3.2 | Pre-trained models which are used for development are monitored as part of AI system regular monitoring and maintenance. | subcategory |
| nist-ai-rmf:MANAGE 4 | Risk treatments including response and recovery, and communication plans to the identified and measured AI risks are documented and monitored regularly. | category |
| nist-ai-rmf:MANAGE 4.1 | Post-deployment AI system monitoring plans are implemented, including mechanisms for capturing and evaluating input from users and other relevant AI actors, appeal and override, de | subcategory |
| nist-ai-rmf:MANAGE 4.2 | Measurable activities for continual improvements are integrated into AI system updates and include regular engagement with interested parties, including relevant AI actors. | subcategory |
| nist-ai-rmf:MANAGE 4.3 | Incidents and errors are communicated to relevant AI actors including affected communities. Processes for tracking, responding to, and recovering from incidents and errors are foll | subcategory |
| nist-ai-rmf:MAP | Context is recognized and risks related to context are identified. | function |
| nist-ai-rmf:MAP 1 | Context is established and understood. | category |
| nist-ai-rmf:MAP 1.1 | Intended purpose, potentially beneficial uses, context-specific laws, norms and expectations, and prospective settings in which the AI system will be deployed are understood and do | subcategory |
| nist-ai-rmf:MAP 1.2 | Inter-disciplinary AI actors, competencies, skills and capacities for establishing context reflect demographic diversity and broad domain and user experience expertise, and their p | subcategory |
| nist-ai-rmf:MAP 1.3 | The organization’s mission and relevant goals for the AI technology are understood and documented. | subcategory |
| nist-ai-rmf:MAP 1.4 | The business value or context of business use has been clearly defined or– in the case of assessing existing AI systems – re-evaluated. | subcategory |
| nist-ai-rmf:MAP 1.5 | Organizational risk tolerances are determined and documented. | subcategory |
| nist-ai-rmf:MAP 1.6 | System requirements (e.g., “the system shall respect the privacy of its users”) are elicited from and understood by relevant AI actors. Design decisions take socio-technical implic | subcategory |
| nist-ai-rmf:MAP 2 | Categorization of the AI system is performed. | category |
| nist-ai-rmf:MAP 2.1 | The specific task, and methods used to implement the task, that the AI system will support is defined (e.g., classifiers, generative models, recommenders). | subcategory |
| nist-ai-rmf:MAP 2.2 | Information about the AI system’s knowledge limits and how system output may be utilized and overseen by humans is documented. Documentation provides sufficient information to assi | subcategory |
| nist-ai-rmf:MAP 2.3 | Scientific integrity and TEVV considerations are identified and documented, including those related to experimental design, data collection and selection(e.g., availability, repres | subcategory |
| nist-ai-rmf:MAP 3 | AI capabilities, targeted usage, goals, and expected benefits and costs compared with appropriate benchmarks are understood. | category |
| nist-ai-rmf:MAP 3.1 | Potential benefits of intended AI system functionality and performance are examined and documented. | subcategory |
| nist-ai-rmf:MAP 3.2 | Potential costs, including non-monetary costs, which result from expected or realized AI errors or system functionality and trustworthiness - as connected to organizational risk to | subcategory |
| nist-ai-rmf:MAP 3.3 | Targeted application scope is specified and documented based on the system's capability, established context, and AI system categorization. | subcategory |
| nist-ai-rmf:MAP 3.4 | Processes for operator and practitioner proficiency with AI system performance and trustworthiness – and relevant technical standards and certifications – are defined, assessed and | subcategory |
| nist-ai-rmf:MAP 3.5 | Processes for human oversight are defined, assessed, and documented in accordance with organizational policies from GOVERN function. | subcategory |
| nist-ai-rmf:MAP 4 | Risks and benefits are mapped for all components of the AI system including third-party software and data. | category |
| nist-ai-rmf:MAP 4.1 | Approaches for mapping AI technology and legal risks of its components –including the use of third-party data or software – are in place, followed, and documented, as are risks of  | subcategory |
| nist-ai-rmf:MAP 4.2 | Internal risk controls for components of the AI system including third-party AI technologies are identified and documented. | subcategory |
| nist-ai-rmf:MAP 5 | Impacts to individuals, groups, communities, organizations, and society are characterized. | category |
| nist-ai-rmf:MAP 5.1 | Likelihood and magnitude of each identified impact (both potentially beneficial and harmful) based on expected use, past uses of AI systems in similar contexts, public incident rep | subcategory |
| nist-ai-rmf:MAP 5.2 | Practices and personnel for supporting regular engagement with relevant AI actors and integrating feedback about positive, negative, and unanticipated impacts are in place and docu | subcategory |
| nist-ai-rmf:MEASURE | Identified risks are assessed, analyzed, or tracked. | function |
| nist-ai-rmf:MEASURE 1 | Appropriate methods and metrics are identified and applied. | category |
| nist-ai-rmf:MEASURE 1.1 | Approaches and metrics for measurement of AI risks enumerated during the Map function are selected for implementation starting with the most significant AI risks. The risks or trus | subcategory |
| nist-ai-rmf:MEASURE 1.2 | Appropriateness of AI metrics and effectiveness of existing controls is regularly assessed and updated including reports of errors and impacts on affected communities. | subcategory |
| nist-ai-rmf:MEASURE 1.3 | Internal experts who did not serve as front-line developers for the system and/or independent assessors are involved in regular assessments and updates. Domain experts, users, AI a | subcategory |
| nist-ai-rmf:MEASURE 2 | AI systems are evaluated for trustworthy characteristics. | category |
| nist-ai-rmf:MEASURE 2.1 | Test sets, metrics, and details about the tools used during test, evaluation, validation, and verification (TEVV) are documented. | subcategory |
| nist-ai-rmf:MEASURE 2.10 | Privacy risk of the AI system – as identified in the MAP function – is examined and documented. | subcategory |
| nist-ai-rmf:MEASURE 2.11 | Fairness and bias – as identified in the MAP function – is evaluated and results are documented. | subcategory |
| nist-ai-rmf:MEASURE 2.12 | Environmental impact and sustainability of AI model training and management activities – as identified in the MAP function – are assessed and documented. | subcategory |
| nist-ai-rmf:MEASURE 2.13 | Effectiveness of the employed TEVV metrics and processes in the measure function are evaluated and documented. | subcategory |
| nist-ai-rmf:MEASURE 2.2 | Evaluations involving human subjects meet applicable requirements(including human subject protection) and are representative of the relevant population. | subcategory |
| nist-ai-rmf:MEASURE 2.3 | AI system performance or assurance criteria are measured qualitatively or quantitatively and demonstrated for conditions similar to deployment setting(s). measures are documented. | subcategory |
| nist-ai-rmf:MEASURE 2.4 | The functionality and behavior of the AI system and its components – as identified in the MAP function – are monitored when in production. | subcategory |
| nist-ai-rmf:MEASURE 2.5 | The AI system to be deployed is demonstrated to be valid and reliable. Limitations of the generalizability beyond the conditions under which the technology was developed are docume | subcategory |
| nist-ai-rmf:MEASURE 2.6 | AI system is evaluated regularly for safety risks – as identified in the MAP function. The AI system to be deployed is demonstrated to be safe, its residual negative risk does not  | subcategory |
| nist-ai-rmf:MEASURE 2.7 | AI system security and resilience – as identified in the MAP function – are evaluated and documented. | subcategory |
| nist-ai-rmf:MEASURE 2.8 | Risks associated with transparency and accountability – as identified in the MAP function – are examined and documented. | subcategory |
| nist-ai-rmf:MEASURE 2.9 | The AI model is explained, validated, and documented, and an AI system output is interpreted within its context – as identified in the MAP function –and to inform responsible use a | subcategory |
| nist-ai-rmf:MEASURE 3 | Mechanisms for tracking identified AI risks over time are in place. | category |
| nist-ai-rmf:MEASURE 3.1 | Approaches, personnel, and documentation are in place to regularly identify and track existing, unanticipated, and emergent AI risks based on factors such as intended and actual pe | subcategory |
| nist-ai-rmf:MEASURE 3.2 | Risk tracking approaches are considered for settings where AI risks are difficult to assess using currently available measurement techniques or where metrics are not yet available. | subcategory |
| nist-ai-rmf:MEASURE 3.3 | Feedback processes for end users and impacted communities to report problems and appeal system outcomes are established and integrated into AI system evaluation metrics. | subcategory |
| nist-ai-rmf:MEASURE 4 | Feedback about efficacy of measurement is gathered and assessed. | category |
| nist-ai-rmf:MEASURE 4.1 | measurement approaches for identifying AI risks are connected to deployment context(s) and informed through consultation with domain experts and other end users. Approaches are doc | subcategory |
| nist-ai-rmf:MEASURE 4.2 | measurement results regarding AI system trustworthiness in deployment context(s) and across AI lifecycle are informed by input from domain experts and other relevant AI actors to v | subcategory |
| nist-ai-rmf:MEASURE 4.3 | Measurable performance improvements or declines based on consultations with relevant AI actors including affected communities, and field data about context-relevant risks and trust | subcategory |

## NIST Cybersecurity Framework

| ID | Name | Kind |
| --- | --- | --- |
| nist-csf:DE | DETECT | function |
| nist-csf:DE.AE | Adverse Event Analysis | category |
| nist-csf:DE.AE-01 | A baseline of network operations and expected data flows for users and systems is established and managed | subcategory (deprecated) |
| nist-csf:DE.AE-02 | Potentially adverse events are analyzed to better understand associated activities | subcategory |
| nist-csf:DE.AE-03 | Information is correlated from multiple sources | subcategory |
| nist-csf:DE.AE-04 | The estimated impact and scope of adverse events are understood | subcategory |
| nist-csf:DE.AE-05 | Incident alert thresholds are established | subcategory (deprecated) |
| nist-csf:DE.AE-06 | Information on adverse events is provided to authorized staff and tools | subcategory |
| nist-csf:DE.AE-07 | Cyber threat intelligence and other contextual information are integrated into the analysis | subcategory |
| nist-csf:DE.AE-08 | Incidents are declared when adverse events meet the defined incident criteria | subcategory |
| nist-csf:DE.CM | Continuous Monitoring | category |
| nist-csf:DE.CM-01 | Networks and network services are monitored to find potentially adverse events | subcategory |
| nist-csf:DE.CM-02 | The physical environment is monitored to find potentially adverse events | subcategory |
| nist-csf:DE.CM-03 | Personnel activity and technology usage are monitored to find potentially adverse events | subcategory |
| nist-csf:DE.CM-04 | Malicious code is detected | subcategory (deprecated) |
| nist-csf:DE.CM-05 | Unauthorized mobile code is detected | subcategory (deprecated) |
| nist-csf:DE.CM-06 | External service provider activities and services are monitored to find potentially adverse events | subcategory |
| nist-csf:DE.CM-07 | Monitoring for unauthorized personnel, connections, devices, and software is performed | subcategory (deprecated) |
| nist-csf:DE.CM-08 | Vulnerability scans are performed | subcategory (deprecated) |
| nist-csf:DE.CM-09 | Computing hardware and software, runtime environments, and their data are monitored to find potentially adverse events | subcategory |
| nist-csf:DE.DP | Detection Processes | category (deprecated) |
| nist-csf:DE.DP-01 | Roles and responsibilities for detection are well defined to ensure accountability | subcategory (deprecated) |
| nist-csf:DE.DP-02 | Detection activities comply with all applicable requirements | subcategory (deprecated) |
| nist-csf:DE.DP-03 | Detection processes are tested | subcategory (deprecated) |
| nist-csf:DE.DP-04 | Event detection information is communicated | subcategory (deprecated) |
| nist-csf:DE.DP-05 | Detection processes are continuously improved | subcategory (deprecated) |
| nist-csf:GV | GOVERN | function |
| nist-csf:GV.OC | Organizational Context | category |
| nist-csf:GV.OC-01 | The organizational mission is understood and informs cybersecurity risk management | subcategory |
| nist-csf:GV.OC-02 | Internal and external stakeholders are understood, and their needs and expectations regarding cybersecurity risk management are understood and considered | subcategory |
| nist-csf:GV.OC-03 | Legal, regulatory, and contractual requirements regarding cybersecurity - including privacy and civil liberties obligations - are understood and managed | subcategory |
| nist-csf:GV.OC-04 | Critical objectives, capabilities, and services that external stakeholders depend on or expect from the organization are understood and communicated | subcategory |
| nist-csf:GV.OC-05 | Outcomes, capabilities, and services that the organization depends on are understood and communicated | subcategory |
| nist-csf:GV.OV | Oversight | category |
| nist-csf:GV.OV-01 | Cybersecurity risk management strategy outcomes are reviewed to inform and adjust strategy and direction | subcategory |
| nist-csf:GV.OV-02 | The cybersecurity risk management strategy is reviewed and adjusted to ensure coverage of organizational requirements and risks | subcategory |
| nist-csf:GV.OV-03 | Organizational cybersecurity risk management performance is evaluated and reviewed for adjustments needed | subcategory |
| nist-csf:GV.PO | Policy | category |
| nist-csf:GV.PO-01 | Policy for managing cybersecurity risks is established based on organizational context, cybersecurity strategy, and priorities and is communicated and enforced | subcategory |
| nist-csf:GV.PO-02 | Policy for managing cybersecurity risks is reviewed, updated, communicated, and enforced to reflect changes in requirements, threats, technology, and organizational mission | subcategory |
| nist-csf:GV.RM | Risk Management Strategy | category |
| nist-csf:GV.RM-01 | Risk management objectives are established and agreed to by organizational stakeholders | subcategory |
| nist-csf:GV.RM-02 | Risk appetite and risk tolerance statements are established, communicated, and maintained | subcategory |
| nist-csf:GV.RM-03 | Cybersecurity risk management activities and outcomes are included in enterprise risk management processes | subcategory |
| nist-csf:GV.RM-04 | Strategic direction that describes appropriate risk response options is established and communicated | subcategory |
| nist-csf:GV.RM-05 | Lines of communication across the organization are established for cybersecurity risks, including risks from suppliers and other third parties | subcategory |
| nist-csf:GV.RM-06 | A standardized method for calculating, documenting, categorizing, and prioritizing cybersecurity risks is established and communicated | subcategory |
| nist-csf:GV.RM-07 | Strategic opportunities (i.e., positive risks) are characterized and are included in organizational cybersecurity risk discussions | subcategory |
| nist-csf:GV.RR | Roles, Responsibilities, and Authorities | category |
| nist-csf:GV.RR-01 | Organizational leadership is responsible and accountable for cybersecurity risk and fosters a culture that is risk-aware, ethical, and continually improving | subcategory |
| nist-csf:GV.RR-02 | Roles, responsibilities, and authorities related to cybersecurity risk management are established, communicated, understood, and enforced | subcategory |
| nist-csf:GV.RR-03 | Adequate resources are allocated commensurate with the cybersecurity risk strategy, roles, responsibilities, and policies | subcategory |
| nist-csf:GV.RR-04 | Cybersecurity is included in human resources practices | subcategory |
| nist-csf:GV.SC | Cybersecurity Supply Chain Risk Management | category |
| nist-csf:GV.SC-01 | A cybersecurity supply chain risk management program, strategy, objectives, policies, and processes are established and agreed to by organizational stakeholders | subcategory |
| nist-csf:GV.SC-02 | Cybersecurity roles and responsibilities for suppliers, customers, and partners are established, communicated, and coordinated internally and externally | subcategory |
| nist-csf:GV.SC-03 | Cybersecurity supply chain risk management is integrated into cybersecurity and enterprise risk management, risk assessment, and improvement processes | subcategory |
| nist-csf:GV.SC-04 | Suppliers are known and prioritized by criticality | subcategory |
| nist-csf:GV.SC-05 | Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts and other types of agreements with suppliers and other rele | subcategory |
| nist-csf:GV.SC-06 | Planning and due diligence are performed to reduce risks before entering into formal supplier or other third-party relationships | subcategory |
| nist-csf:GV.SC-07 | The risks posed by a supplier, their products and services, and other third parties are understood, recorded, prioritized, assessed, responded to, and monitored over the course of  | subcategory |
| nist-csf:GV.SC-08 | Relevant suppliers and other third parties are included in incident planning, response, and recovery activities | subcategory |
| nist-csf:GV.SC-09 | Supply chain security practices are integrated into cybersecurity and enterprise risk management programs, and their performance is monitored throughout the technology product and  | subcategory |
| nist-csf:GV.SC-10 | Cybersecurity supply chain risk management plans include provisions for activities that occur after the conclusion of a partnership or service agreement | subcategory |
| nist-csf:ID | IDENTIFY | function |
| nist-csf:ID.AM | Asset Management | category |
| nist-csf:ID.AM-01 | Inventories of hardware managed by the organization are maintained | subcategory |
| nist-csf:ID.AM-02 | Inventories of software, services, and systems managed by the organization are maintained | subcategory |
| nist-csf:ID.AM-03 | Representations of the organization's authorized network communication and internal and external network data flows are maintained | subcategory |
| nist-csf:ID.AM-04 | Inventories of services provided by suppliers are maintained | subcategory |
| nist-csf:ID.AM-05 | Assets are prioritized based on classification, criticality, resources, and impact on the mission | subcategory |
| nist-csf:ID.AM-06 | Cybersecurity roles and responsibilities for the entire workforce and third-party stakeholders (e.g., suppliers, customers, partners) are established | subcategory (deprecated) |
| nist-csf:ID.AM-07 | Inventories of data and corresponding metadata for designated data types are maintained | subcategory |
| nist-csf:ID.AM-08 | Systems, hardware, software, services, and data are managed throughout their life cycles | subcategory |
| nist-csf:ID.BE | Business Environment | category (deprecated) |
| nist-csf:ID.BE-01 | The organization’s role in the supply chain is identified and communicated | subcategory (deprecated) |
| nist-csf:ID.BE-02 | The organization’s place in critical infrastructure and its industry sector is identified and communicated | subcategory (deprecated) |
| nist-csf:ID.BE-03 | Priorities for organizational mission, objectives, and activities are established and communicated | subcategory (deprecated) |
| nist-csf:ID.BE-04 | Dependencies and critical functions for delivery of critical services are established | subcategory (deprecated) |
| nist-csf:ID.BE-05 | Resilience requirements to support delivery of critical services are established for all operating states (e.g. under duress/attack, during recovery, normal operations) | subcategory (deprecated) |
| nist-csf:ID.GV | Governance | category (deprecated) |
| nist-csf:ID.GV-01 | Organizational cybersecurity policy is established and communicated | subcategory (deprecated) |
| nist-csf:ID.GV-02 | Cybersecurity roles and responsibilities are coordinated and aligned with internal roles and external partners | subcategory (deprecated) |
| nist-csf:ID.GV-03 | Legal and regulatory requirements regarding cybersecurity, including privacy and civil liberties obligations, are understood and managed | subcategory (deprecated) |
| nist-csf:ID.GV-04 | Governance and risk management processes address cybersecurity risks | subcategory (deprecated) |
| nist-csf:ID.IM | Improvement | category |
| nist-csf:ID.IM-01 | Improvements are identified from evaluations | subcategory |
| nist-csf:ID.IM-02 | Improvements are identified from security tests and exercises, including those done in coordination with suppliers and relevant third parties | subcategory |
| nist-csf:ID.IM-03 | Improvements are identified from execution of operational processes, procedures, and activities | subcategory |
| nist-csf:ID.IM-04 | Incident response plans and other cybersecurity plans that affect operations are established, communicated, maintained, and improved | subcategory |
| nist-csf:ID.RA | Risk Assessment | category |
| nist-csf:ID.RA-01 | Vulnerabilities in assets are identified, validated, and recorded | subcategory |
| nist-csf:ID.RA-02 | Cyber threat intelligence is received from information sharing forums and sources | subcategory |
| nist-csf:ID.RA-03 | Internal and external threats to the organization are identified and recorded | subcategory |
| nist-csf:ID.RA-04 | Potential impacts and likelihoods of threats exploiting vulnerabilities are identified and recorded | subcategory |
| nist-csf:ID.RA-05 | Threats, vulnerabilities, likelihoods, and impacts are used to understand inherent risk and inform risk response prioritization | subcategory |
| nist-csf:ID.RA-06 | Risk responses are chosen, prioritized, planned, tracked, and communicated | subcategory |
| nist-csf:ID.RA-07 | Changes and exceptions are managed, assessed for risk impact, recorded, and tracked | subcategory |
| nist-csf:ID.RA-08 | Processes for receiving, analyzing, and responding to vulnerability disclosures are established | subcategory |
| nist-csf:ID.RA-09 | The authenticity and integrity of hardware and software are assessed prior to acquisition and use | subcategory |
| nist-csf:ID.RA-10 | Critical suppliers are assessed prior to acquisition | subcategory |
| nist-csf:ID.RM | Risk Management Strategy | category (deprecated) |
| nist-csf:ID.RM-01 | Risk management processes are established, managed, and agreed to by organizational stakeholders | subcategory (deprecated) |
| nist-csf:ID.RM-02 | Organizational risk tolerance is determined and clearly expressed | subcategory (deprecated) |
| nist-csf:ID.RM-03 | The organization’s determination of risk tolerance is informed by its role in critical infrastructure and sector specific risk analysis | subcategory (deprecated) |
| nist-csf:ID.SC | Supply Chain Risk Management | category (deprecated) |
| nist-csf:ID.SC-01 | Cyber supply chain risk management processes are identified, established, assessed, managed, and agreed to by organizational stakeholders | subcategory (deprecated) |
| nist-csf:ID.SC-02 | Suppliers and third party partners of information systems, components, and services are identified, prioritized, and assessed using a cyber supply chain risk assessment process | subcategory (deprecated) |
| nist-csf:ID.SC-03 | Contracts with suppliers and third-party partners are used to implement appropriate measures designed to meet the objectives of an organization’s cybersecurity program and Cyber Su | subcategory (deprecated) |
| nist-csf:ID.SC-04 | Suppliers and third-party partners are routinely assessed using audits, test results, or other forms of evaluations to confirm they are meeting their contractual obligations. | subcategory (deprecated) |
| nist-csf:ID.SC-05 | Response and recovery planning and testing are conducted with suppliers and third-party providers | subcategory (deprecated) |
| nist-csf:PR | PROTECT | function |
| nist-csf:PR.AA | Identity Management, Authentication, and Access Control | category |
| nist-csf:PR.AA-01 | Identities and credentials for authorized users, services, and hardware are managed by the organization | subcategory |
| nist-csf:PR.AA-02 | Identities are proofed and bound to credentials based on the context of interactions | subcategory |
| nist-csf:PR.AA-03 | Users, services, and hardware are authenticated | subcategory |
| nist-csf:PR.AA-04 | Identity assertions are protected, conveyed, and verified | subcategory |
| nist-csf:PR.AA-05 | Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed, and incorporate the principles of least privilege and separation of d | subcategory |
| nist-csf:PR.AA-06 | Physical access to assets is managed, monitored, and enforced commensurate with risk | subcategory |
| nist-csf:PR.AC | Identity Management, Authentication and Access Control | category (deprecated) |
| nist-csf:PR.AC-01 | Identities and credentials are issued, managed, verified, revoked, and audited for authorized devices, users and processes | subcategory (deprecated) |
| nist-csf:PR.AC-02 | Physical access to assets is managed and protected | subcategory (deprecated) |
| nist-csf:PR.AC-03 | Remote access is managed | subcategory (deprecated) |
| nist-csf:PR.AC-04 | Access permissions and authorizations are managed, incorporating the principles of least privilege and separation of duties | subcategory (deprecated) |
| nist-csf:PR.AC-05 | Network integrity is protected (e.g., network segregation, network segmentation) | subcategory (deprecated) |
| nist-csf:PR.AC-06 | Identities are proofed and bound to credentials and asserted in interactions | subcategory (deprecated) |
| nist-csf:PR.AC-07 | Users, devices, and other assets are authenticated (e.g., single-factor, multi-factor) commensurate with the risk of the transaction (e.g., individuals’ security and privacy risks  | subcategory (deprecated) |
| nist-csf:PR.AT | Awareness and Training | category |
| nist-csf:PR.AT-01 | Personnel are provided with awareness and training so that they possess the knowledge and skills to perform general tasks with cybersecurity risks in mind | subcategory |
| nist-csf:PR.AT-02 | Individuals in specialized roles are provided with awareness and training so that they possess the knowledge and skills to perform relevant tasks with cybersecurity risks in mind | subcategory |
| nist-csf:PR.AT-03 | Third-party stakeholders (e.g., suppliers, customers, partners) understand their roles and responsibilities | subcategory (deprecated) |
| nist-csf:PR.AT-04 | Senior executives understand their roles and responsibilities | subcategory (deprecated) |
| nist-csf:PR.AT-05 | Physical and cybersecurity personnel understand their roles and responsibilities | subcategory (deprecated) |
| nist-csf:PR.DS | Data Security | category |
| nist-csf:PR.DS-01 | The confidentiality, integrity, and availability of data-at-rest are protected | subcategory |
| nist-csf:PR.DS-02 | The confidentiality, integrity, and availability of data-in-transit are protected | subcategory |
| nist-csf:PR.DS-03 | Assets are formally managed throughout removal, transfers, and disposition | subcategory (deprecated) |
| nist-csf:PR.DS-04 | Adequate capacity to ensure availability is maintained | subcategory (deprecated) |
| nist-csf:PR.DS-05 | Protections against data leaks are implemented | subcategory (deprecated) |
| nist-csf:PR.DS-06 | Integrity checking mechanisms are used to verify software, firmware, and information integrity | subcategory (deprecated) |
| nist-csf:PR.DS-07 | The development and testing environment(s) are separate from the production environment | subcategory (deprecated) |
| nist-csf:PR.DS-08 | Integrity checking mechanisms are used to verify hardware integrity | subcategory (deprecated) |
| nist-csf:PR.DS-10 | The confidentiality, integrity, and availability of data-in-use are protected | subcategory |
| nist-csf:PR.DS-11 | Backups of data are created, protected, maintained, and tested | subcategory |
| nist-csf:PR.IP | Information Protection Processes and Procedures | category (deprecated) |
| nist-csf:PR.IP-01 | A baseline configuration of information technology/industrial control systems is created and maintained incorporating security principles (e.g. concept of least functionality) | subcategory (deprecated) |
| nist-csf:PR.IP-02 | A System Development Life Cycle to manage systems is implemented | subcategory (deprecated) |
| nist-csf:PR.IP-03 | Configuration change control processes are in place | subcategory (deprecated) |
| nist-csf:PR.IP-04 | Backups of information are conducted, maintained, and tested | subcategory (deprecated) |
| nist-csf:PR.IP-05 | Policy and regulations regarding the physical operating environment for organizational assets are met | subcategory (deprecated) |
| nist-csf:PR.IP-06 | Data is destroyed according to policy | subcategory (deprecated) |
| nist-csf:PR.IP-07 | Protection processes are improved | subcategory (deprecated) |
| nist-csf:PR.IP-08 | Effectiveness of protection technologies is shared | subcategory (deprecated) |
| nist-csf:PR.IP-09 | Response plans (Incident Response and Business Continuity) and recovery plans (Incident Recovery and Disaster Recovery) are in place and managed | subcategory (deprecated) |
| nist-csf:PR.IP-10 | Response and recovery plans are tested | subcategory (deprecated) |
| nist-csf:PR.IP-11 | Cybersecurity is included in human resources practices (e.g., deprovisioning, personnel screening) | subcategory (deprecated) |
| nist-csf:PR.IP-12 | A vulnerability management plan is developed and implemented | subcategory (deprecated) |
| nist-csf:PR.IR | Technology Infrastructure Resilience | category |
| nist-csf:PR.IR-01 | Networks and environments are protected from unauthorized logical access and usage | subcategory |
| nist-csf:PR.IR-02 | The organization's technology assets are protected from environmental threats | subcategory |
| nist-csf:PR.IR-03 | Mechanisms are implemented to achieve resilience requirements in normal and adverse situations | subcategory |
| nist-csf:PR.IR-04 | Adequate resource capacity to ensure availability is maintained | subcategory |
| nist-csf:PR.MA | Maintenance | category (deprecated) |
| nist-csf:PR.MA-01 | Maintenance and repair of organizational assets are performed and logged, with approved and controlled tools | subcategory (deprecated) |
| nist-csf:PR.MA-02 | Remote maintenance of organizational assets is approved, logged, and performed in a manner that prevents unauthorized access | subcategory (deprecated) |
| nist-csf:PR.PS | Platform Security | category |
| nist-csf:PR.PS-01 | Configuration management practices are established and applied | subcategory |
| nist-csf:PR.PS-02 | Software is maintained, replaced, and removed commensurate with risk | subcategory |
| nist-csf:PR.PS-03 | Hardware is maintained, replaced, and removed commensurate with risk | subcategory |
| nist-csf:PR.PS-04 | Log records are generated and made available for continuous monitoring | subcategory |
| nist-csf:PR.PS-05 | Installation and execution of unauthorized software are prevented | subcategory |
| nist-csf:PR.PS-06 | Secure software development practices are integrated, and their performance is monitored throughout the software development life cycle | subcategory |
| nist-csf:PR.PT | Protective Technology | category (deprecated) |
| nist-csf:PR.PT-01 | Audit/log records are determined, documented, implemented, and reviewed in accordance with policy | subcategory (deprecated) |
| nist-csf:PR.PT-02 | Removable media is protected and its use restricted according to policy | subcategory (deprecated) |
| nist-csf:PR.PT-03 | The principle of least functionality is incorporated by configuring systems to provide only essential capabilities | subcategory (deprecated) |
| nist-csf:PR.PT-04 | Communications and control networks are protected | subcategory (deprecated) |
| nist-csf:PR.PT-05 | Mechanisms (e.g., failsafe, load balancing, hot swap) are implemented to achieve resilience requirements in normal and adverse situations | subcategory (deprecated) |
| nist-csf:RC | RECOVER | function |
| nist-csf:RC.CO | Incident Recovery Communication | category |
| nist-csf:RC.CO-01 | Public relations are managed | subcategory (deprecated) |
| nist-csf:RC.CO-02 | Reputation is repaired after an incident | subcategory (deprecated) |
| nist-csf:RC.CO-03 | Recovery activities and progress in restoring operational capabilities are communicated to designated internal and external stakeholders | subcategory |
| nist-csf:RC.CO-04 | Public updates on incident recovery are shared using approved methods and messaging | subcategory |
| nist-csf:RC.IM | Improvements | category (deprecated) |
| nist-csf:RC.IM-01 | Recovery plans incorporate lessons learned | subcategory (deprecated) |
| nist-csf:RC.IM-02 | Recovery strategies are updated | subcategory (deprecated) |
| nist-csf:RC.RP | Incident Recovery Plan Execution | category |
| nist-csf:RC.RP-01 | The recovery portion of the incident response plan is executed once initiated from the incident response process | subcategory |
| nist-csf:RC.RP-02 | Recovery actions are selected, scoped, prioritized, and performed | subcategory |
| nist-csf:RC.RP-03 | The integrity of backups and other restoration assets is verified before using them for restoration | subcategory |
| nist-csf:RC.RP-04 | Critical mission functions and cybersecurity risk management are considered to establish post-incident operational norms | subcategory |
| nist-csf:RC.RP-05 | The integrity of restored assets is verified, systems and services are restored, and normal operating status is confirmed | subcategory |
| nist-csf:RC.RP-06 | The end of incident recovery is declared based on criteria, and incident-related documentation is completed | subcategory |
| nist-csf:RS | RESPOND | function |
| nist-csf:RS.AN | Incident Analysis | category |
| nist-csf:RS.AN-01 | Notifications from detection systems are investigated | subcategory (deprecated) |
| nist-csf:RS.AN-02 | The impact of the incident is understood | subcategory (deprecated) |
| nist-csf:RS.AN-03 | Analysis is performed to establish what has taken place during an incident and the root cause of the incident | subcategory |
| nist-csf:RS.AN-04 | Incidents are categorized consistent with response plans | subcategory (deprecated) |
| nist-csf:RS.AN-05 | Processes are established to receive, analyze and respond to vulnerabilities disclosed to the organization from internal and external sources (e.g. internal testing, security bulle | subcategory (deprecated) |
| nist-csf:RS.AN-06 | Actions performed during an investigation are recorded, and the records' integrity and provenance are preserved | subcategory |
| nist-csf:RS.AN-07 | Incident data and metadata are collected, and their integrity and provenance are preserved | subcategory |
| nist-csf:RS.AN-08 | An incident's magnitude is estimated and validated | subcategory |
| nist-csf:RS.CO | Incident Response Reporting and Communication | category |
| nist-csf:RS.CO-01 | Personnel know their roles and order of operations when a response is needed | subcategory (deprecated) |
| nist-csf:RS.CO-02 | Internal and external stakeholders are notified of incidents | subcategory |
| nist-csf:RS.CO-03 | Information is shared with designated internal and external stakeholders | subcategory |
| nist-csf:RS.CO-04 | Coordination with stakeholders occurs consistent with response plans | subcategory (deprecated) |
| nist-csf:RS.CO-05 | Voluntary information sharing occurs with external stakeholders to achieve broader cybersecurity situational awareness | subcategory (deprecated) |
| nist-csf:RS.IM | Improvements | category (deprecated) |
| nist-csf:RS.IM-01 | Response plans incorporate lessons learned | subcategory (deprecated) |
| nist-csf:RS.IM-02 | Response strategies are updated | subcategory (deprecated) |
| nist-csf:RS.MA | Incident Management | category |
| nist-csf:RS.MA-01 | The incident response plan is executed in coordination with relevant third parties once an incident is declared | subcategory |
| nist-csf:RS.MA-02 | Incident reports are triaged and validated | subcategory |
| nist-csf:RS.MA-03 | Incidents are categorized and prioritized | subcategory |
| nist-csf:RS.MA-04 | Incidents are escalated or elevated as needed | subcategory |
| nist-csf:RS.MA-05 | The criteria for initiating incident recovery are applied | subcategory |
| nist-csf:RS.MI | Incident Mitigation | category |
| nist-csf:RS.MI-01 | Incidents are contained | subcategory |
| nist-csf:RS.MI-02 | Incidents are eradicated | subcategory |
| nist-csf:RS.MI-03 | Newly identified vulnerabilities are mitigated or documented as accepted risks | subcategory (deprecated) |
| nist-csf:RS.RP | Response Planning | category (deprecated) |
| nist-csf:RS.RP-01 | Response plan is executed during or after an incident | subcategory (deprecated) |

## NIST Secure Software Development Framework

| ID | Name | Kind |
| --- | --- | --- |
| nist-ssdf:PO | Prepare the Organization | group |
| nist-ssdf:PO.1 | Define Security Requirements for Software Development | practice |
| nist-ssdf:PO.1.1 | Identify and document all security requirements for the organization’s software development infrastructures and processes, and maintain the requirements over time. | task |
| nist-ssdf:PO.1.2 | Identify and document all security requirements for organization-developed software to meet, and maintain the requirements over time. | task |
| nist-ssdf:PO.1.3 | Communicate requirements to all third parties who will provide commercial software components to the organization for reuse by the organization’s own software. .Formerly PW.3.1 | task |
| nist-ssdf:PO.2 | Implement Roles and Responsibilities | practice |
| nist-ssdf:PO.2.1 | Create new roles and alter responsibilities for existing roles as needed to encompass all parts of the SDLC. Periodically review and maintain the defined roles and responsibilities | task |
| nist-ssdf:PO.2.2 | Provide role-based training for all personnel with responsibilities that contribute to secure development. Periodically review personnel proficiency and role-based training, and up | task |
| nist-ssdf:PO.2.3 | Obtain upper management or authorizing official commitment to secure development, and convey that commitment to all with development-related roles and responsibilities. | task |
| nist-ssdf:PO.3 | Implement Supporting Toolchains | practice |
| nist-ssdf:PO.3.1 | Specify which tools or tool types must or should be included in each toolchain to mitigate identified risks, as well as how the toolchain components are to be integrated with each  | task |
| nist-ssdf:PO.3.2 | Follow recommended security practices to deploy, operate, and maintain tools and toolchains. | task |
| nist-ssdf:PO.3.3 | Configure tools to generate artifacts of their support of secure software development practices as defined by the organization. | task |
| nist-ssdf:PO.4 | Define and Use Criteria for Software Security Checks | practice |
| nist-ssdf:PO.4.1 | Define criteria for software security checks and track throughout the SDLC. | task |
| nist-ssdf:PO.4.2 | Implement processes, mechanisms, etc. to gather and safeguard the necessary information in support of the criteria. | task |
| nist-ssdf:PO.5 | Implement and Maintain Secure Environments for Software Development | practice |
| nist-ssdf:PO.5.1 | Separate and protect each environment involved in software development. | task |
| nist-ssdf:PO.5.2 | Secure and harden development endpoints (i.e., endpoints for software designers, developers, testers, builders, etc.) to perform development-related tasks using a risk-based approa | task |
| nist-ssdf:PS | Protect Software | group |
| nist-ssdf:PS.1 | Protect All Forms of Code from Unauthorized Access and Tampering | practice |
| nist-ssdf:PS.1.1 | Store all forms of code – including source code, executable code, and configuration-as-code – based on the principle of least privilege so that only authorized personnel, tools, se | task |
| nist-ssdf:PS.2 | Provide a Mechanism for Verifying Software Release Integrity | practice |
| nist-ssdf:PS.2.1 | Make software integrity verification information available to software acquirers. | task |
| nist-ssdf:PS.3 | Archive and Protect Each Software Release | practice |
| nist-ssdf:PS.3.1 | Securely archive the necessary files and supporting data (e.g., integrity verification information, provenance data) to be retained for each software release. | task |
| nist-ssdf:PS.3.2 | Collect, safeguard, maintain, and share provenance data for all components of each software release (e.g., in a software bill of materials .SBOM). | task |
| nist-ssdf:PW | Produce Well-Secured Software | group |
| nist-ssdf:PW.1 | Design Software to Meet Security Requirements and Mitigate Security Risks | practice |
| nist-ssdf:PW.1.1 | Use forms of risk modeling – such as threat modeling, attack modeling, or attack surface mapping – to help assess the security risk for the software. | task |
| nist-ssdf:PW.1.2 | Track and maintain the software’s security requirements, risks, and design decisions. | task |
| nist-ssdf:PW.1.3 | Where appropriate, build in support for using standardized security features and services (e.g., enabling software to integrate with existing log management, identity management, a | task |
| nist-ssdf:PW.2 | Review the Software Design to Verify Compliance with Security Requirements and Risk Information | practice |
| nist-ssdf:PW.2.1 | Have 1) a qualified person (or people) who were not involved with the design and/or 2) automated processes instantiated in the toolchain review the software design to confirm and e | task |
| nist-ssdf:PW.4 | Reuse Existing, Well-Secured Software When Feasible Instead of Duplicating Functionality | practice |
| nist-ssdf:PW.4.1 | Acquire and maintain well-secured software components (e.g., software libraries, modules, middleware, frameworks) from commercial, open-source, and other third-party developers for | task |
| nist-ssdf:PW.4.2 | Create and maintain well-secured software components in-house following SDLC processes to meet common internal software development needs that cannot be better met by third-party s | task |
| nist-ssdf:PW.4.4 | Verify that acquired commercial, open-source, and all other third-party software components comply with the requirements, as defined by the organization, throughout their life cycl | task |
| nist-ssdf:PW.5 | Create Source Code by Adhering to Secure Coding Practices | practice |
| nist-ssdf:PW.5.1 | Follow all secure coding practices that are appropriate to the development languages and environment to meet the organization’s requirements. | task |
| nist-ssdf:PW.6 | Configure the Compilation, Interpreter, and Build Processes to Improve Executable Security | practice |
| nist-ssdf:PW.6.1 | Use compiler, interpreter, and build tools that offer features to improve executable security. | task |
| nist-ssdf:PW.6.2 | Determine which compiler, interpreter, and build tool features should be used and how each should be configured, then implement and use the approved configurations. | task |
| nist-ssdf:PW.7 | Review and/or Analyze Human-Readable Code to Identify Vulnerabilities and Verify Compliance with Security Requirements | practice |
| nist-ssdf:PW.7.1 | Determine whether code review (a person looks directly at the code to find issues) and/or code analysis (tools are used to find issues in code, either in a fully automated way or i | task |
| nist-ssdf:PW.7.2 | Perform the code review and/or code analysis based on the organization’s secure coding standards, and record and triage all discovered issues and recommended remediations in the de | task |
| nist-ssdf:PW.8 | Test Executable Code to Identify Vulnerabilities and Verify Compliance with Security Requirements | practice |
| nist-ssdf:PW.8.1 | Determine whether executable code testing should be performed to find vulnerabilities not identified by previous reviews, analysis, or testing and, if so, which types of testing sh | task |
| nist-ssdf:PW.8.2 | Scope the testing, design the tests, perform the testing, and document the results, including recording and triaging all discovered issues and recommended remediations in the devel | task |
| nist-ssdf:PW.9 | Configure Software to Have Secure Settings by Default | practice |
| nist-ssdf:PW.9.1 | Define a secure baseline by determining how to configure each setting that has an effect on security or a security-related setting so that the default settings are secure and do no | task |
| nist-ssdf:PW.9.2 | Implement the default settings (or groups of default settings, if applicable), and document each setting for software administrators. | task |
| nist-ssdf:RV | Respond to Vulnerabilities | group |
| nist-ssdf:RV.1 | Identify and Confirm Vulnerabilities on an Ongoing Basis | practice |
| nist-ssdf:RV.1.1 | Gather information from software acquirers, users, and public sources on potential vulnerabilities in the software and third-party components that the software uses, and investigat | task |
| nist-ssdf:RV.1.2 | Review, analyze, and/or test the software’s code to identify or confirm the presence of previously undetected vulnerabilities. | task |
| nist-ssdf:RV.1.3 | Have a policy that addresses vulnerability disclosure and remediation, and implement the roles, responsibilities, and processes needed to support that policy. | task |
| nist-ssdf:RV.2 | Assess, Prioritize, and Remediate Vulnerabilities | practice |
| nist-ssdf:RV.2.1 | Analyze each vulnerability to gather sufficient information about risk to plan its remediation or other risk response. | task |
| nist-ssdf:RV.2.2 | Plan and implement risk responses for vulnerabilities. | task |
| nist-ssdf:RV.3 | Analyze Vulnerabilities to Identify Their Root Causes | practice |
| nist-ssdf:RV.3.1 | Analyze identified vulnerabilities to determine their root causes. | task |
| nist-ssdf:RV.3.2 | Analyze the root causes over time to identify patterns, such as a particular secure coding practice not being followed consistently. | task |
| nist-ssdf:RV.3.3 | Review the software for similar vulnerabilities to eradicate a class of vulnerabilities, and proactively fix them rather than waiting for external reports. | task |
| nist-ssdf:RV.3.4 | Review the SDLC process, and update it if appropriate to prevent (or reduce the likelihood of) the root cause recurring in updates to the software or in new software that is create | task |

## OWASP API Security Top 10

| ID | Name | Kind |
| --- | --- | --- |
| owasp-api:API1 | Broken object level authorization | risk |
| owasp-api:API10 | Unsafe consumption of apis | risk |
| owasp-api:API2 | Broken authentication | risk |
| owasp-api:API3 | Broken object property level authorization | risk |
| owasp-api:API4 | Unrestricted resource consumption | risk |
| owasp-api:API5 | Broken function level authorization | risk |
| owasp-api:API6 | Unrestricted access to sensitive business flows | risk |
| owasp-api:API7 | Server side request forgery | risk |
| owasp-api:API8 | Security misconfiguration | risk |
| owasp-api:API9 | Improper inventory management | risk |

## OWASP Application Security Verification Standard

| ID | Name | Kind |
| --- | --- | --- |
| owasp-asvs:V1.1.1 | Verify that input is decoded or unescaped into a canonical form only once, it is only decoded when encoded data in that form is expected, and that this is done before processing the input further, for example it is not performed after input validation or sanitization. | verification_requirement |
| owasp-asvs:V1.1.2 | Verify that the application performs output encoding and escaping either as a final step before being used by the interpreter for which it is intended or by the interpreter itself. | verification_requirement |
| owasp-asvs:V1.2.1 | Verify that output encoding for an HTTP response, HTML document, or XML document is relevant for the context required, such as encoding the relevant characters for HTML elements, HTML attributes, HTML comments, CSS, or HTTP header fields, to avoid changing the message or document structure. | verification_requirement |
| owasp-asvs:V1.2.10 | Verify that the application is protected against CSV and Formula Injection. The application must follow the escaping rules defined in RFC 4180 sections 2.6 and 2.7 when exporting CSV content. Additionally, when exporting to CSV or other spreadsheet formats (such as XLS, XLSX, or ODF), special characters (including '=', '+', '-', '@', '\t' (tab), and '\0' (null character)) must be escaped with a single quote if they appear as the first character in a field value. | verification_requirement |
| owasp-asvs:V1.2.2 | Verify that when dynamically building URLs, untrusted data is encoded according to its context (e.g., URL encoding or base64url encoding for query or path parameters). Ensure that only safe URL protocols are permitted (e.g., disallow javascript: or data:). | verification_requirement |
| owasp-asvs:V1.2.3 | Verify that output encoding or escaping is used when dynamically building JavaScript content (including JSON), to avoid changing the message or document structure (to avoid JavaScript and JSON injection). | verification_requirement |
| owasp-asvs:V1.2.4 | Verify that data selection or database queries (e.g., SQL, HQL, NoSQL, Cypher) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from SQL Injection and other database injection attacks. This is also relevant when writing stored procedures. | verification_requirement |
| owasp-asvs:V1.2.5 | Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding. | verification_requirement |
| owasp-asvs:V1.2.6 | Verify that the application protects against LDAP injection vulnerabilities, or that specific security controls to prevent LDAP injection have been implemented. | verification_requirement |
| owasp-asvs:V1.2.7 | Verify that the application is protected against XPath injection attacks by using query parameterization or precompiled queries. | verification_requirement |
| owasp-asvs:V1.2.8 | Verify that LaTeX processors are configured securely (such as not using the "--shell-escape" flag) and an allowlist of commands is used to prevent LaTeX injection attacks. | verification_requirement |
| owasp-asvs:V1.2.9 | Verify that the application escapes special characters in regular expressions (typically using a backslash) to prevent them from being misinterpreted as metacharacters. | verification_requirement |
| owasp-asvs:V1.3.1 | Verify that all untrusted HTML input from WYSIWYG editors or similar is sanitized using a well-known and secure HTML sanitization library or framework feature. | verification_requirement |
| owasp-asvs:V1.3.10 | Verify that format strings which might resolve in an unexpected or malicious way when used are sanitized before being processed. | verification_requirement |
| owasp-asvs:V1.3.11 | Verify that the application sanitizes user input before passing to mail systems to protect against SMTP or IMAP injection. | verification_requirement |
| owasp-asvs:V1.3.12 | Verify that regular expressions are free from elements causing exponential backtracking, and ensure untrusted input is sanitized to mitigate ReDoS or Runaway Regex attacks. | verification_requirement |
| owasp-asvs:V1.3.2 | Verify that the application avoids the use of eval() or other dynamic code execution features such as Spring Expression Language (SpEL). Where there is no alternative, any user input being included must be sanitized before being executed. | verification_requirement |
| owasp-asvs:V1.3.3 | Verify that data being passed to a potentially dangerous context is sanitized beforehand to enforce safety measures, such as only allowing characters which are safe for this context and trimming input which is too long. | verification_requirement |
| owasp-asvs:V1.3.4 | Verify that user-supplied Scalable Vector Graphics (SVG) scriptable content is validated or sanitized to contain only tags and attributes (such as draw graphics) that are safe for the application, e.g., do not contain scripts and foreignObject. | verification_requirement |
| owasp-asvs:V1.3.5 | Verify that the application sanitizes or disables user-supplied scriptable or expression template language content, such as Markdown, CSS or XSL stylesheets, BBCode, or similar. | verification_requirement |
| owasp-asvs:V1.3.6 | Verify that the application protects against Server-side Request Forgery (SSRF) attacks, by validating untrusted data against an allowlist of protocols, domains, paths and ports and sanitizing potentially dangerous characters before using the data to call another service. | verification_requirement |
| owasp-asvs:V1.3.7 | Verify that the application protects against template injection attacks by not allowing templates to be built based on untrusted input. Where there is no alternative, any untrusted input being included dynamically during template creation must be sanitized or strictly validated. | verification_requirement |
| owasp-asvs:V1.3.8 | Verify that the application appropriately sanitizes untrusted input before use in Java Naming and Directory Interface (JNDI) queries and that JNDI is configured securely to prevent JNDI injection attacks. | verification_requirement |
| owasp-asvs:V1.3.9 | Verify that the application sanitizes content before it is sent to memcache to prevent injection attacks. | verification_requirement |
| owasp-asvs:V1.4.1 | Verify that the application uses memory-safe string, safer memory copy and pointer arithmetic to detect or prevent stack, buffer, or heap overflows. | verification_requirement |
| owasp-asvs:V1.4.2 | Verify that sign, range, and input validation techniques are used to prevent integer overflows. | verification_requirement |
| owasp-asvs:V1.4.3 | Verify that dynamically allocated memory and resources are released, and that references or pointers to freed memory are removed or set to null to prevent dangling pointers and use-after-free vulnerabilities. | verification_requirement |
| owasp-asvs:V1.5.1 | Verify that the application configures XML parsers to use a restrictive configuration and that unsafe features such as resolving external entities are disabled to prevent XML eXternal Entity (XXE) attacks. | verification_requirement |
| owasp-asvs:V1.5.2 | Verify that deserialization of untrusted data enforces safe input handling, such as using an allowlist of object types or restricting client-defined object types, to prevent deserialization attacks. Deserialization mechanisms that are explicitly defined as insecure must not be used with untrusted input. | verification_requirement |
| owasp-asvs:V1.5.3 | Verify that different parsers used in the application for the same data type (e.g., JSON parsers, XML parsers, URL parsers), perform parsing in a consistent way and use the same character encoding mechanism to avoid issues such as JSON Interoperability vulnerabilities or different URI or file parsing behavior being exploited in Remote File Inclusion (RFI) or Server-side Request Forgery (SSRF) attacks. | verification_requirement |
| owasp-asvs:V10.1.1 | Verify that tokens are only sent to components that strictly need them. For example, when using a backend-for-frontend pattern for browser-based JavaScript applications, access and refresh tokens shall only be accessible for the backend. | verification_requirement |
| owasp-asvs:V10.1.2 | Verify that the client only accepts values from the authorization server (such as the authorization code or ID Token) if these values result from an authorization flow that was initiated by the same user agent session and transaction. This requires that client-generated secrets, such as the proof key for code exchange (PKCE) 'code_verifier', 'state' or OIDC 'nonce', are not guessable, are specific to the transaction, and are securely bound to both the client and the user agent session in which the transaction was started. | verification_requirement |
| owasp-asvs:V10.2.1 | Verify that, if the code flow is used, the OAuth client has protection against browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF), which trigger token requests, either by using proof key for code exchange (PKCE) functionality or checking the 'state' parameter that was sent in the authorization request. | verification_requirement |
| owasp-asvs:V10.2.2 | Verify that, if the OAuth client can interact with more than one authorization server, it has a defense against mix-up attacks. For example, it could require that the authorization server return the 'iss' parameter value and validate it in the authorization response and the token response. | verification_requirement |
| owasp-asvs:V10.2.3 | Verify that the OAuth client only requests the required scopes (or other authorization parameters) in requests to the authorization server. | verification_requirement |
| owasp-asvs:V10.3.1 | Verify that the resource server only accepts access tokens that are intended for use with that service (audience). The audience may be included in a structured access token (such as the 'aud' claim in JWT), or it can be checked using the token introspection endpoint. | verification_requirement |
| owasp-asvs:V10.3.2 | Verify that the resource server enforces authorization decisions based on claims from the access token that define delegated authorization. If claims such as 'sub', 'scope', and 'authorization_details' are present, they must be part of the decision. | verification_requirement |
| owasp-asvs:V10.3.3 | Verify that if an access control decision requires identifying a unique user from an access token (JWT or related token introspection response), the resource server identifies the user from claims that cannot be reassigned to other users. Typically, it means using a combination of 'iss' and 'sub' claims. | verification_requirement |
| owasp-asvs:V10.3.4 | Verify that, if the resource server requires specific authentication strength, methods, or recentness, it verifies that the presented access token satisfies these constraints. For example, if present, using the OIDC 'acr', 'amr' and 'auth_time' claims respectively. | verification_requirement |
| owasp-asvs:V10.3.5 | Verify that the resource server prevents the use of stolen access tokens or replay of access tokens (from unauthorized parties) by requiring sender-constrained access tokens, either Mutual TLS for OAuth 2 or OAuth 2 Demonstration of Proof of Possession (DPoP). | verification_requirement |
| owasp-asvs:V10.4.1 | Verify that the authorization server validates redirect URIs based on a client-specific allowlist of pre-registered URIs using exact string comparison. | verification_requirement |
| owasp-asvs:V10.4.10 | Verify that confidential client is authenticated for client-to-authorized server backchannel requests such as token requests, pushed authorization requests (PAR), and token revocation requests. | verification_requirement |
| owasp-asvs:V10.4.11 | Verify that the authorization server configuration only assigns the required scopes to the OAuth client. | verification_requirement |
| owasp-asvs:V10.4.12 | Verify that for a given client, the authorization server only allows the 'response_mode' value that this client needs to use. For example, by having the authorization server validate this value against the expected values or by using pushed authorization request (PAR) or JWT-secured Authorization Request (JAR). | verification_requirement |
| owasp-asvs:V10.4.13 | Verify that grant type 'code' is always used together with pushed authorization requests (PAR). | verification_requirement |
| owasp-asvs:V10.4.14 | Verify that the authorization server issues only sender-constrained (Proof-of-Possession) access tokens, either with certificate-bound access tokens using mutual TLS (mTLS) or DPoP-bound access tokens (Demonstration of Proof of Possession). | verification_requirement |
| owasp-asvs:V10.4.15 | Verify that, for a server-side client (which is not executed on the end-user device), the authorization server ensures that the 'authorization_details' parameter value is from the client backend and that the user has not tampered with it. For example, by requiring the usage of pushed authorization request (PAR) or JWT-secured Authorization Request (JAR). | verification_requirement |
| owasp-asvs:V10.4.16 | Verify that the client is confidential and the authorization server requires the use of strong client authentication methods (based on public-key cryptography and resistant to replay attacks), such as mutual TLS ('tls_client_auth', 'self_signed_tls_client_auth') or private key JWT ('private_key_jwt'). | verification_requirement |
| owasp-asvs:V10.4.2 | Verify that, if the authorization server returns the authorization code in the authorization response, it can be used only once for a token request. For the second valid request with an authorization code that has already been used to issue an access token, the authorization server must reject a token request and revoke any issued tokens related to the authorization code. | verification_requirement |
| owasp-asvs:V10.4.3 | Verify that the authorization code is short-lived. The maximum lifetime can be up to 10 minutes for L1 and L2 applications and up to 1 minute for L3 applications. | verification_requirement |
| owasp-asvs:V10.4.4 | Verify that for a given client, the authorization server only allows the usage of grants that this client needs to use. Note that the grants 'token' (Implicit flow) and 'password' (Resource Owner Password Credentials flow) must no longer be used. | verification_requirement |
| owasp-asvs:V10.4.5 | Verify that the authorization server mitigates refresh token replay attacks for public clients, preferably using sender-constrained refresh tokens, i.e., Demonstrating Proof of Possession (DPoP) or Certificate-Bound Access Tokens using mutual TLS (mTLS). For L1 and L2 applications, refresh token rotation may be used. If refresh token rotation is used, the authorization server must invalidate the refresh token after usage, and revoke all refresh tokens for that authorization if an already used and invalidated refresh token is provided. | verification_requirement |
| owasp-asvs:V10.4.6 | Verify that, if the code grant is used, the authorization server mitigates authorization code interception attacks by requiring proof key for code exchange (PKCE). For authorization requests, the authorization server must require a valid 'code_challenge' value and must not accept a 'code_challenge_method' value of 'plain'. For a token request, it must require validation of the 'code_verifier' parameter. | verification_requirement |
| owasp-asvs:V10.4.7 | Verify that if the authorization server supports unauthenticated dynamic client registration, it mitigates the risk of malicious client applications. It must validate client metadata such as any registered URIs, ensure the user's consent, and warn the user before processing an authorization request with an untrusted client application. | verification_requirement |
| owasp-asvs:V10.4.8 | Verify that refresh tokens have an absolute expiration, including if sliding refresh token expiration is applied. | verification_requirement |
| owasp-asvs:V10.4.9 | Verify that refresh tokens and reference access tokens can be revoked by an authorized user using the authorization server user interface, to mitigate the risk of malicious clients or stolen tokens. | verification_requirement |
| owasp-asvs:V10.5.1 | Verify that the client (as the relying party) mitigates ID Token replay attacks. For example, by ensuring that the 'nonce' claim in the ID Token matches the 'nonce' value sent in the authentication request to the OpenID Provider (in OAuth2 refereed to as the authorization request sent to the authorization server). | verification_requirement |
| owasp-asvs:V10.5.2 | Verify that the client uniquely identifies the user from ID Token claims, usually the 'sub' claim, which cannot be reassigned to other users (for the scope of an identity provider). | verification_requirement |
| owasp-asvs:V10.5.3 | Verify that the client rejects attempts by a malicious authorization server to impersonate another authorization server through authorization server metadata. The client must reject authorization server metadata if the issuer URL in the authorization server metadata does not exactly match the pre-configured issuer URL expected by the client. | verification_requirement |
| owasp-asvs:V10.5.4 | Verify that the client validates that the ID Token is intended to be used for that client (audience) by checking that the 'aud' claim from the token is equal to the 'client_id' value for the client. | verification_requirement |
| owasp-asvs:V10.5.5 | Verify that, when using OIDC back-channel logout, the relying party mitigates denial of service through forced logout and cross-JWT confusion in the logout flow. The client must verify that the logout token is correctly typed with a value of 'logout+jwt', contains the 'event' claim with the correct member name, and does not contain a 'nonce' claim. Note that it is also recommended to have a short expiration (e.g., 2 minutes). | verification_requirement |
| owasp-asvs:V10.6.1 | Verify that the OpenID Provider only allows values 'code', 'ciba', 'id_token', or 'id_token code' for response mode. Note that 'code' is preferred over 'id_token code' (the OIDC Hybrid flow), and 'token' (any Implicit flow) must not be used. | verification_requirement |
| owasp-asvs:V10.6.2 | Verify that the OpenID Provider mitigates denial of service through forced logout. By obtaining explicit confirmation from the end-user or, if present, validating parameters in the logout request (initiated by the relying party), such as the 'id_token_hint'. | verification_requirement |
| owasp-asvs:V10.7.1 | Verify that the authorization server ensures that the user consents to each authorization request. If the identity of the client cannot be assured, the authorization server must always explicitly prompt the user for consent. | verification_requirement |
| owasp-asvs:V10.7.2 | Verify that when the authorization server prompts for user consent, it presents sufficient and clear information about what is being consented to. When applicable, this should include the nature of the requested authorizations (typically based on scope, resource server, Rich Authorization Requests (RAR) authorization details), the identity of the authorized application, and the lifetime of these authorizations. | verification_requirement |
| owasp-asvs:V10.7.3 | Verify that the user can review, modify, and revoke consents which the user has granted through the authorization server. | verification_requirement |
| owasp-asvs:V11.1.1 | Verify that there is a documented policy for management of cryptographic keys and a cryptographic key lifecycle that follows a key management standard such as NIST SP 800-57. This should include ensuring that keys are not overshared (for example, with more than two entities for shared secrets and more than one entity for private keys). | verification_requirement |
| owasp-asvs:V11.1.2 | Verify that a cryptographic inventory is performed, maintained, regularly updated, and includes all cryptographic keys, algorithms, and certificates used by the application. It must also document where keys can and cannot be used in the system, and the types of data that can and cannot be protected using the keys. | verification_requirement |
| owasp-asvs:V11.1.3 | Verify that cryptographic discovery mechanisms are employed to identify all instances of cryptography in the system, including encryption, hashing, and signing operations. | verification_requirement |
| owasp-asvs:V11.1.4 | Verify that a cryptographic inventory is maintained. This must include a documented plan that outlines the migration path to new cryptographic standards, such as post-quantum cryptography, in order to react to future threats. | verification_requirement |
| owasp-asvs:V11.2.1 | Verify that industry-validated implementations (including libraries and hardware-accelerated implementations) are used for cryptographic operations. | verification_requirement |
| owasp-asvs:V11.2.2 | Verify that the application is designed with crypto agility such that random number, authenticated encryption, MAC, or hashing algorithms, key lengths, rounds, ciphers and modes can be reconfigured, upgraded, or swapped at any time, to protect against cryptographic breaks. Similarly, it must also be possible to replace keys and passwords and re-encrypt data. This will allow for seamless upgrades to post-quantum cryptography (PQC), once high-assurance implementations of approved PQC schemes or standards are widely available. | verification_requirement |
| owasp-asvs:V11.2.3 | Verify that all cryptographic primitives utilize a minimum of 128-bits of security based on the algorithm, key size, and configuration. For example, a 256-bit ECC key provides roughly 128 bits of security where RSA requires a 3072-bit key to achieve 128 bits of security. | verification_requirement |
| owasp-asvs:V11.2.4 | Verify that all cryptographic operations are constant-time, with no 'short-circuit' operations in comparisons, calculations, or returns, to avoid leaking information. | verification_requirement |
| owasp-asvs:V11.2.5 | Verify that all cryptographic modules fail securely, and errors are handled in a way that does not enable vulnerabilities, such as Padding Oracle attacks. | verification_requirement |
| owasp-asvs:V11.3.1 | Verify that insecure block modes (e.g., ECB) and weak padding schemes (e.g., PKCS#1 v1.5) are not used. | verification_requirement |
| owasp-asvs:V11.3.2 | Verify that only approved ciphers and modes such as AES with GCM are used. | verification_requirement |
| owasp-asvs:V11.3.3 | Verify that encrypted data is protected against unauthorized modification preferably by using an approved authenticated encryption method or by combining an approved encryption method with an approved MAC algorithm. | verification_requirement |
| owasp-asvs:V11.3.4 | Verify that nonces, initialization vectors, and other single-use numbers are not used for more than one encryption key and data-element pair. The method of generation must be appropriate for the algorithm being used. | verification_requirement |
| owasp-asvs:V11.3.5 | Verify that any combination of an encryption algorithm and a MAC algorithm is operating in encrypt-then-MAC mode. | verification_requirement |
| owasp-asvs:V11.4.1 | Verify that only approved hash functions are used for general cryptographic use cases, including digital signatures, HMAC, KDF, and random bit generation. Disallowed hash functions, such as MD5, must not be used for any cryptographic purpose. | verification_requirement |
| owasp-asvs:V11.4.2 | Verify that passwords are stored using an approved, computationally intensive, key derivation function (also known as a "password hashing function"), with parameter settings configured based on current guidance. The settings should balance security and performance to make brute-force attacks sufficiently challenging for the required level of security. | verification_requirement |
| owasp-asvs:V11.4.3 | Verify that hash functions used in digital signatures, as part of data authentication or data integrity are collision resistant and have appropriate bit-lengths. If collision resistance is required, the output length must be at least 256 bits. If only resistance to second pre-image attacks is required, the output length must be at least 128 bits. | verification_requirement |
| owasp-asvs:V11.4.4 | Verify that the application uses approved key derivation functions with key stretching parameters when deriving secret keys from passwords. The parameters in use must balance security and performance to prevent brute-force attacks from compromising the resulting cryptographic key. | verification_requirement |
| owasp-asvs:V11.5.1 | Verify that all random numbers and strings which are intended to be non-guessable must be generated using a cryptographically secure pseudo-random number generator (CSPRNG) and have at least 128 bits of entropy. Note that UUIDs do not respect this condition. | verification_requirement |
| owasp-asvs:V11.5.2 | Verify that the random number generation mechanism in use is designed to work securely, even under heavy demand. | verification_requirement |
| owasp-asvs:V11.6.1 | Verify that only approved cryptographic algorithms and modes of operation are used for key generation and seeding, and digital signature generation and verification. Key generation algorithms must not generate insecure keys vulnerable to known attacks, for example, RSA keys which are vulnerable to Fermat factorization. | verification_requirement |
| owasp-asvs:V11.6.2 | Verify that approved cryptographic algorithms are used for key exchange (such as Diffie-Hellman) with a focus on ensuring that key exchange mechanisms use secure parameters. This will prevent attacks on the key establishment process which could lead to adversary-in-the-middle attacks or cryptographic breaks. | verification_requirement |
| owasp-asvs:V11.7.1 | Verify that full memory encryption is in use that protects sensitive data while it is in use, preventing access by unauthorized users or processes. | verification_requirement |
| owasp-asvs:V11.7.2 | Verify that data minimization ensures the minimal amount of data is exposed during processing, and ensure that data is encrypted immediately after use or as soon as feasible. | verification_requirement |
| owasp-asvs:V12.1.1 | Verify that only the latest recommended versions of the TLS protocol are enabled, such as TLS 1.2 and TLS 1.3. The latest version of the TLS protocol must be the preferred option. | verification_requirement |
| owasp-asvs:V12.1.2 | Verify that only recommended cipher suites are enabled, with the strongest cipher suites set as preferred. L3 applications must only support cipher suites which provide forward secrecy. | verification_requirement |
| owasp-asvs:V12.1.3 | Verify that the application validates that mTLS client certificates are trusted before using the certificate identity for authentication or authorization. | verification_requirement |
| owasp-asvs:V12.1.4 | Verify that proper certification revocation, such as Online Certificate Status Protocol (OCSP) Stapling, is enabled and configured. | verification_requirement |
| owasp-asvs:V12.1.5 | Verify that Encrypted Client Hello (ECH) is enabled in the application's TLS settings to prevent exposure of sensitive metadata, such as the Server Name Indication (SNI), during TLS handshake processes. | verification_requirement |
| owasp-asvs:V12.2.1 | Verify that TLS is used for all connectivity between a client and external facing, HTTP-based services, and does not fall back to insecure or unencrypted communications. | verification_requirement |
| owasp-asvs:V12.2.2 | Verify that external facing services use publicly trusted TLS certificates. | verification_requirement |
| owasp-asvs:V12.3.1 | Verify that an encrypted protocol such as TLS is used for all inbound and outbound connections to and from the application, including monitoring systems, management tools, remote access and SSH, middleware, databases, mainframes, partner systems, or external APIs. The server must not fall back to insecure or unencrypted protocols. | verification_requirement |
| owasp-asvs:V12.3.2 | Verify that TLS clients validate certificates received before communicating with a TLS server. | verification_requirement |
| owasp-asvs:V12.3.3 | Verify that TLS or another appropriate transport encryption mechanism used for all connectivity between internal, HTTP-based services within the application, and does not fall back to insecure or unencrypted communications. | verification_requirement |
| owasp-asvs:V12.3.4 | Verify that TLS connections between internal services use trusted certificates. Where internally generated or self-signed certificates are used, the consuming service must be configured to only trust specific internal CAs and specific self-signed certificates. | verification_requirement |
| owasp-asvs:V12.3.5 | Verify that services communicating internally within a system (intra-service communications) use strong authentication to ensure that each endpoint is verified. Strong authentication methods, such as TLS client authentication, must be employed to ensure identity, using public-key infrastructure and mechanisms that are resistant to replay attacks. For microservice architectures, consider using a service mesh to simplify certificate management and enhance security. | verification_requirement |
| owasp-asvs:V13.1.1 | Verify that all communication needs for the application are documented. This must include external services which the application relies upon and cases where an end user might be able to provide an external location to which the application will then connect. | verification_requirement |
| owasp-asvs:V13.1.2 | Verify that for each service the application uses, the documentation defines the maximum number of concurrent connections (e.g., connection pool limits) and how the application behaves when that limit is reached, including any fallback or recovery mechanisms, to prevent denial of service conditions. | verification_requirement |
| owasp-asvs:V13.1.3 | Verify that the application documentation defines resource‑management strategies for every external system or service it uses (e.g., databases, file handles, threads, HTTP connections). This should include resource‑release procedures, timeout settings, failure handling, and where retry logic is implemented, specifying retry limits, delays, and back‑off algorithms. For synchronous HTTP request–response operations it should mandate short timeouts and either disable retries or strictly limit retries to prevent cascading delays and resource exhaustion. | verification_requirement |
| owasp-asvs:V13.1.4 | Verify that the application's documentation defines the secrets that are critical for the security of the application and a schedule for rotating them, based on the organization's threat model and business requirements. | verification_requirement |
| owasp-asvs:V13.2.1 | Verify that communications between backend application components that don't support the application's standard user session mechanism, including APIs, middleware, and data layers, are authenticated. Authentication must use individual service accounts, short-term tokens, or certificate-based authentication and not unchanging credentials such as passwords, API keys, or shared accounts with privileged access. | verification_requirement |
| owasp-asvs:V13.2.2 | Verify that communications between backend application components, including local or operating system services, APIs, middleware, and data layers, are performed with accounts assigned the least necessary privileges. | verification_requirement |
| owasp-asvs:V13.2.3 | Verify that if a credential has to be used for service authentication, the credential being used by the consumer is not a default credential (e.g., root/root or admin/admin). | verification_requirement |
| owasp-asvs:V13.2.4 | Verify that an allowlist is used to define the external resources or systems with which the application is permitted to communicate (e.g., for outbound requests, data loads, or file access). This allowlist can be implemented at the application layer, web server, firewall, or a combination of different layers. | verification_requirement |
| owasp-asvs:V13.2.5 | Verify that the web or application server is configured with an allowlist of resources or systems to which the server can send requests or load data or files from. | verification_requirement |
| owasp-asvs:V13.2.6 | Verify that where the application connects to separate services, it follows the documented configuration for each connection, such as maximum parallel connections, behavior when maximum allowed connections is reached, connection timeouts, and retry strategies. | verification_requirement |
| owasp-asvs:V13.3.1 | Verify that a secrets management solution, such as a key vault, is used to securely create, store, control access to, and destroy backend secrets. These could include passwords, key material, integrations with databases and third-party systems, keys and seeds for time-based tokens, other internal secrets, and API keys. Secrets must not be included in application source code or included in build artifacts. For an L3 application, this must involve a hardware-backed solution such as an HSM. | verification_requirement |
| owasp-asvs:V13.3.2 | Verify that access to secret assets adheres to the principle of least privilege. | verification_requirement |
| owasp-asvs:V13.3.3 | Verify that all cryptographic operations are performed using an isolated security module (such as a vault or hardware security module) to securely manage and protect key material from exposure outside of the security module. | verification_requirement |
| owasp-asvs:V13.3.4 | Verify that secrets are configured to expire and be rotated based on the application's documentation. | verification_requirement |
| owasp-asvs:V13.4.1 | Verify that the application is deployed either without any source control metadata, including the .git or .svn folders, or in a way that these folders are inaccessible both externally and to the application itself. | verification_requirement |
| owasp-asvs:V13.4.2 | Verify that debug modes are disabled for all components in production environments to prevent exposure of debugging features and information leakage. | verification_requirement |
| owasp-asvs:V13.4.3 | Verify that web servers do not expose directory listings to clients unless explicitly intended. | verification_requirement |
| owasp-asvs:V13.4.4 | Verify that using the HTTP TRACE method is not supported in production environments, to avoid potential information leakage. | verification_requirement |
| owasp-asvs:V13.4.5 | Verify that documentation (such as for internal APIs) and monitoring endpoints are not exposed unless explicitly intended. | verification_requirement |
| owasp-asvs:V13.4.6 | Verify that the application does not expose detailed version information of backend components. | verification_requirement |
| owasp-asvs:V13.4.7 | Verify that the web tier is configured to only serve files with specific file extensions to prevent unintentional information, configuration, and source code leakage. | verification_requirement |
| owasp-asvs:V14.1.1 | Verify that all sensitive data created and processed by the application has been identified and classified into protection levels. This includes data that is only encoded and therefore easily decoded, such as Base64 strings or the plaintext payload inside a JWT. Protection levels need to take into account any data protection and privacy regulations and standards which the application is required to comply with. | verification_requirement |
| owasp-asvs:V14.1.2 | Verify that all sensitive data protection levels have a documented set of protection requirements. This must include (but not be limited to) requirements related to general encryption, integrity verification, retention, how the data is to be logged, access controls around sensitive data in logs, database-level encryption, privacy and privacy-enhancing technologies to be used, and other confidentiality requirements. | verification_requirement |
| owasp-asvs:V14.2.1 | Verify that sensitive data is only sent to the server in the HTTP message body or header fields, and that the URL and query string do not contain sensitive information, such as an API key or session token. | verification_requirement |
| owasp-asvs:V14.2.2 | Verify that the application prevents sensitive data from being cached in server components, such as load balancers and application caches, or ensures that the data is securely purged after use. | verification_requirement |
| owasp-asvs:V14.2.3 | Verify that defined sensitive data is not sent to untrusted parties (e.g., user trackers) to prevent unwanted collection of data outside of the application's control. | verification_requirement |
| owasp-asvs:V14.2.4 | Verify that controls around sensitive data related to encryption, integrity verification, retention, how the data is to be logged, access controls around sensitive data in logs, privacy and privacy-enhancing technologies, are implemented as defined in the documentation for the specific data's protection level. | verification_requirement |
| owasp-asvs:V14.2.5 | Verify that caching mechanisms are configured to only cache responses which have the expected content type for that resource and do not contain sensitive, dynamic content. The web server should return a 404 or 302 response when a non-existent file is accessed rather than returning a different, valid file. This should prevent Web Cache Deception attacks. | verification_requirement |
| owasp-asvs:V14.2.6 | Verify that the application only returns the minimum required sensitive data for the application's functionality. For example, only returning some of the digits of a credit card number and not the full number. If the complete data is required, it should be masked in the user interface unless the user specifically views it. | verification_requirement |
| owasp-asvs:V14.2.7 | Verify that sensitive information is subject to data retention classification, ensuring that outdated or unnecessary data is deleted automatically, on a defined schedule, or as the situation requires. | verification_requirement |
| owasp-asvs:V14.2.8 | Verify that sensitive information is removed from the metadata of user-submitted files unless storage is consented to by the user. | verification_requirement |
| owasp-asvs:V14.3.1 | Verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated. The 'Clear-Site-Data' HTTP response header field may be able to help with this but the client-side should also be able to clear up if the server connection is not available when the session is terminated. | verification_requirement |
| owasp-asvs:V14.3.2 | Verify that the application sets sufficient anti-caching HTTP response header fields (i.e., Cache-Control: no-store) so that sensitive data is not cached in browsers. | verification_requirement |
| owasp-asvs:V14.3.3 | Verify that data stored in browser storage (such as localStorage, sessionStorage, IndexedDB, or cookies) does not contain sensitive data, with the exception of session tokens. | verification_requirement |
| owasp-asvs:V15.1.1 | Verify that application documentation defines risk based remediation time frames for 3rd party component versions with vulnerabilities and for updating libraries in general, to minimize the risk from these components. | verification_requirement |
| owasp-asvs:V15.1.2 | Verify that an inventory catalog, such as software bill of materials (SBOM), is maintained of all third-party libraries in use, including verifying that components come from pre-defined, trusted, and continually maintained repositories. | verification_requirement |
| owasp-asvs:V15.1.3 | Verify that the application documentation identifies functionality which is time-consuming or resource-demanding. This must include how to prevent a loss of availability due to overusing this functionality and how to avoid a situation where building a response takes longer than the consumer's timeout. Potential defenses may include asynchronous processing, using queues, and limiting parallel processes per user and per application. | verification_requirement |
| owasp-asvs:V15.1.4 | Verify that application documentation highlights third-party libraries which are considered to be "risky components". | verification_requirement |
| owasp-asvs:V15.1.5 | Verify that application documentation highlights parts of the application where "dangerous functionality" is being used. | verification_requirement |
| owasp-asvs:V15.2.1 | Verify that the application only contains components which have not breached the documented update and remediation time frames. | verification_requirement |
| owasp-asvs:V15.2.2 | Verify that the application has implemented defenses against loss of availability due to functionality which is time-consuming or resource-demanding, based on the documented security decisions and strategies for this. | verification_requirement |
| owasp-asvs:V15.2.3 | Verify that the production environment only includes functionality that is required for the application to function, and does not expose extraneous functionality such as test code, sample snippets, and development functionality. | verification_requirement |
| owasp-asvs:V15.2.4 | Verify that third-party components and all of their transitive dependencies are included from the expected repository, whether internally owned or an external source, and that there is no risk of a dependency confusion attack. | verification_requirement |
| owasp-asvs:V15.2.5 | Verify that the application implements additional protections around parts of the application which are documented as containing "dangerous functionality" or using third-party libraries considered to be "risky components". This could include techniques such as sandboxing, encapsulation, containerization or network level isolation to delay and deter attackers who compromise one part of an application from pivoting elsewhere in the application. | verification_requirement |
| owasp-asvs:V15.3.1 | Verify that the application only returns the required subset of fields from a data object. For example, it should not return an entire data object, as some individual fields should not be accessible to users. | verification_requirement |
| owasp-asvs:V15.3.2 | Verify that where the application backend makes calls to external URLs, it is configured to not follow redirects unless it is intended functionality. | verification_requirement |
| owasp-asvs:V15.3.3 | Verify that the application has countermeasures to protect against mass assignment attacks by limiting allowed fields per controller and action, e.g., it is not possible to insert or update a field value when it was not intended to be part of that action. | verification_requirement |
| owasp-asvs:V15.3.4 | Verify that all proxying and middleware components transfer the user's original IP address correctly using trusted data fields that cannot be manipulated by the end user, and the application and web server use this correct value for logging and security decisions such as rate limiting, taking into account that even the original IP address may not be reliable due to dynamic IPs, VPNs, or corporate firewalls. | verification_requirement |
| owasp-asvs:V15.3.5 | Verify that the application explicitly ensures that variables are of the correct type and performs strict equality and comparator operations. This is to avoid type juggling or type confusion vulnerabilities caused by the application code making an assumption about a variable type. | verification_requirement |
| owasp-asvs:V15.3.6 | Verify that JavaScript code is written in a way that prevents prototype pollution, for example, by using Set() or Map() instead of object literals. | verification_requirement |
| owasp-asvs:V15.3.7 | Verify that the application has defenses against HTTP parameter pollution attacks, particularly if the application framework makes no distinction about the source of request parameters (query string, body parameters, cookies, or header fields). | verification_requirement |
| owasp-asvs:V15.4.1 | Verify that shared objects in multi-threaded code (such as caches, files, or in-memory objects accessed by multiple threads) are accessed safely by using thread-safe types and synchronization mechanisms like locks or semaphores to avoid race conditions and data corruption. | verification_requirement |
| owasp-asvs:V15.4.2 | Verify that checks on a resource's state, such as its existence or permissions, and the actions that depend on them are performed as a single atomic operation to prevent time-of-check to time-of-use (TOCTOU) race conditions. For example, checking if a file exists before opening it, or verifying a user’s access before granting it. | verification_requirement |
| owasp-asvs:V15.4.3 | Verify that locks are used consistently to avoid threads getting stuck, whether by waiting on each other or retrying endlessly, and that locking logic stays within the code responsible for managing the resource to ensure locks cannot be inadvertently or maliciously modified by external classes or code. | verification_requirement |
| owasp-asvs:V15.4.4 | Verify that resource allocation policies prevent thread starvation by ensuring fair access to resources, such as by leveraging thread pools, allowing lower-priority threads to proceed within a reasonable timeframe. | verification_requirement |
| owasp-asvs:V16.1.1 | Verify that an inventory exists documenting the logging performed at each layer of the application's technology stack, what events are being logged, log formats, where that logging is stored, how it is used, how access to it is controlled, and for how long logs are kept. | verification_requirement |
| owasp-asvs:V16.2.1 | Verify that each log entry includes necessary metadata (such as when, where, who, what) that would allow for a detailed investigation of the timeline when an event happens. | verification_requirement |
| owasp-asvs:V16.2.2 | Verify that time sources for all logging components are synchronized, and that timestamps in security event metadata use UTC or include an explicit time zone offset. UTC is recommended to ensure consistency across distributed systems and to prevent confusion during daylight saving time transitions. | verification_requirement |
| owasp-asvs:V16.2.3 | Verify that the application only stores or broadcasts logs to the files and services that are documented in the log inventory. | verification_requirement |
| owasp-asvs:V16.2.4 | Verify that logs can be read and correlated by the log processor that is in use, preferably by using a common logging format. | verification_requirement |
| owasp-asvs:V16.2.5 | Verify that when logging sensitive data, the application enforces logging based on the data's protection level. For example, it may not be allowed to log certain data, such as credentials or payment details. Other data, such as session tokens, may only be logged by being hashed or masked, either in full or partially. | verification_requirement |
| owasp-asvs:V16.3.1 | Verify that all authentication operations are logged, including successful and unsuccessful attempts. Additional metadata, such as the type of authentication or factors used, should also be collected. | verification_requirement |
| owasp-asvs:V16.3.2 | Verify that failed authorization attempts are logged. For L3, this must include logging all authorization decisions, including logging when sensitive data is accessed (without logging the sensitive data itself). | verification_requirement |
| owasp-asvs:V16.3.3 | Verify that the application logs the security events that are defined in the documentation and also logs attempts to bypass the security controls, such as input validation, business logic, and anti-automation. | verification_requirement |
| owasp-asvs:V16.3.4 | Verify that the application logs unexpected errors and security control failures such as backend TLS failures. | verification_requirement |
| owasp-asvs:V16.4.1 | Verify that all logging components appropriately encode data to prevent log injection. | verification_requirement |
| owasp-asvs:V16.4.2 | Verify that logs are protected from unauthorized access and cannot be modified. | verification_requirement |
| owasp-asvs:V16.4.3 | Verify that logs are securely transmitted to a logically separate system for analysis, detection, alerting, and escalation. The aim is to ensure that if the application is breached, the logs are not compromised. | verification_requirement |
| owasp-asvs:V16.5.1 | Verify that a generic message is returned to the consumer when an unexpected or security-sensitive error occurs, ensuring no exposure of sensitive internal system data such as stack traces, queries, secret keys, and tokens. | verification_requirement |
| owasp-asvs:V16.5.2 | Verify that the application continues to operate securely when external resource access fails, for example, by using patterns such as circuit breakers or graceful degradation. | verification_requirement |
| owasp-asvs:V16.5.3 | Verify that the application fails gracefully and securely, including when an exception occurs, preventing fail-open conditions such as processing a transaction despite errors resulting from validation logic. | verification_requirement |
| owasp-asvs:V16.5.4 | Verify that a "last resort" error handler is defined which will catch all unhandled exceptions. This is both to avoid losing error details that must go to log files and to ensure that an error does not take down the entire application process, leading to a loss of availability. | verification_requirement |
| owasp-asvs:V17.1.1 | Verify that the Traversal Using Relays around NAT (TURN) service only allows access to IP addresses that are not reserved for special purposes (e.g., internal networks, broadcast, loopback). Note that this applies to both IPv4 and IPv6 addresses. | verification_requirement |
| owasp-asvs:V17.1.2 | Verify that the Traversal Using Relays around NAT (TURN) service is not susceptible to resource exhaustion when legitimate users attempt to open a large number of ports on the TURN server. | verification_requirement |
| owasp-asvs:V17.2.1 | Verify that the key for the Datagram Transport Layer Security (DTLS) certificate is managed and protected based on the documented policy for management of cryptographic keys. | verification_requirement |
| owasp-asvs:V17.2.2 | Verify that the media server is configured to use and support approved Datagram Transport Layer Security (DTLS) cipher suites and a secure protection profile for the DTLS Extension for establishing keys for the Secure Real-time Transport Protocol (DTLS-SRTP). | verification_requirement |
| owasp-asvs:V17.2.3 | Verify that Secure Real-time Transport Protocol (SRTP) authentication is checked at the media server to prevent Real-time Transport Protocol (RTP) injection attacks from leading to either a Denial of Service condition or audio or video media insertion into media streams. | verification_requirement |
| owasp-asvs:V17.2.4 | Verify that the media server is able to continue processing incoming media traffic when encountering malformed Secure Real-time Transport Protocol (SRTP) packets. | verification_requirement |
| owasp-asvs:V17.2.5 | Verify that the media server is able to continue processing incoming media traffic during a flood of Secure Real-time Transport Protocol (SRTP) packets from legitimate users. | verification_requirement |
| owasp-asvs:V17.2.6 | Verify that the media server is not susceptible to the "ClientHello" Race Condition vulnerability in Datagram Transport Layer Security (DTLS) by checking if the media server is publicly known to be vulnerable or by performing the race condition test. | verification_requirement |
| owasp-asvs:V17.2.7 | Verify that any audio or video recording mechanisms associated with the media server are able to continue processing incoming media traffic during a flood of Secure Real-time Transport Protocol (SRTP) packets from legitimate users. | verification_requirement |
| owasp-asvs:V17.2.8 | Verify that the Datagram Transport Layer Security (DTLS) certificate is checked against the Session Description Protocol (SDP) fingerprint attribute, terminating the media stream if the check fails, to ensure the authenticity of the media stream. | verification_requirement |
| owasp-asvs:V17.3.1 | Verify that the signaling server is able to continue processing legitimate incoming signaling messages during a flood attack. This should be achieved by implementing rate limiting at the signaling level. | verification_requirement |
| owasp-asvs:V17.3.2 | Verify that the signaling server is able to continue processing legitimate signaling messages when encountering malformed signaling message that could cause a denial of service condition. This could include implementing input validation, safely handling integer overflows, preventing buffer overflows, and employing other robust error-handling techniques. | verification_requirement |
| owasp-asvs:V2.1.1 | Verify that the application's documentation defines input validation rules for how to check the validity of data items against an expected structure. This could be common data formats such as credit card numbers, email addresses, telephone numbers, or it could be an internal data format. | verification_requirement |
| owasp-asvs:V2.1.2 | Verify that the application's documentation defines how to validate the logical and contextual consistency of combined data items, such as checking that suburb and ZIP code match. | verification_requirement |
| owasp-asvs:V2.1.3 | Verify that expectations for business logic limits and validations are documented, including both per-user and globally across the application. | verification_requirement |
| owasp-asvs:V2.2.1 | Verify that input is validated to enforce business or functional expectations for that input. This should either use positive validation against an allow list of values, patterns, and ranges, or be based on comparing the input to an expected structure and logical limits according to predefined rules. For L1, this can focus on input which is used to make specific business or security decisions. For L2 and up, this should apply to all input. | verification_requirement |
| owasp-asvs:V2.2.2 | Verify that the application is designed to enforce input validation at a trusted service layer. While client-side validation improves usability and should be encouraged, it must not be relied upon as a security control. | verification_requirement |
| owasp-asvs:V2.2.3 | Verify that the application ensures that combinations of related data items are reasonable according to the pre-defined rules. | verification_requirement |
| owasp-asvs:V2.3.1 | Verify that the application will only process business logic flows for the same user in the expected sequential step order and without skipping steps. | verification_requirement |
| owasp-asvs:V2.3.2 | Verify that business logic limits are implemented per the application's documentation to avoid business logic flaws being exploited. | verification_requirement |
| owasp-asvs:V2.3.3 | Verify that transactions are being used at the business logic level such that either a business logic operation succeeds in its entirety or it is rolled back to the previous correct state. | verification_requirement |
| owasp-asvs:V2.3.4 | Verify that business logic level locking mechanisms are used to ensure that limited quantity resources (such as theater seats or delivery slots) cannot be double-booked by manipulating the application's logic. | verification_requirement |
| owasp-asvs:V2.3.5 | Verify that high-value business logic flows require multi-user approval to prevent unauthorized or accidental actions. This could include but is not limited to large monetary transfers, contract approvals, access to classified information, or safety overrides in manufacturing. | verification_requirement |
| owasp-asvs:V2.4.1 | Verify that anti-automation controls are in place to protect against excessive calls to application functions that could lead to data exfiltration, garbage-data creation, quota exhaustion, rate-limit breaches, denial-of-service, or overuse of costly resources. | verification_requirement |
| owasp-asvs:V2.4.2 | Verify that business logic flows require realistic human timing, preventing excessively rapid transaction submissions. | verification_requirement |
| owasp-asvs:V3.1.1 | Verify that application documentation states the expected security features that browsers using the application must support (such as HTTPS, HTTP Strict Transport Security (HSTS), Content Security Policy (CSP), and other relevant HTTP security mechanisms). It must also define how the application must behave when some of these features are not available (such as warning the user or blocking access). | verification_requirement |
| owasp-asvs:V3.2.1 | Verify that security controls are in place to prevent browsers from rendering content or functionality in HTTP responses in an incorrect context (e.g., when an API, a user-uploaded file or other resource is requested directly). Possible controls could include: not serving the content unless HTTP request header fields (such as Sec-Fetch-\*) indicate it is the correct context, using the sandbox directive of the Content-Security-Policy header field or using the attachment disposition type in the Content-Disposition header field. | verification_requirement |
| owasp-asvs:V3.2.2 | Verify that content intended to be displayed as text, rather than rendered as HTML, is handled using safe rendering functions (such as createTextNode or textContent) to prevent unintended execution of content such as HTML or JavaScript. | verification_requirement |
| owasp-asvs:V3.2.3 | Verify that the application avoids DOM clobbering when using client-side JavaScript by employing explicit variable declarations, performing strict type checking, avoiding storing global variables on the document object, and implementing namespace isolation. | verification_requirement |
| owasp-asvs:V3.3.1 | Verify that cookies have the 'Secure' attribute set, and if the '\__Host-' prefix is not used for the cookie name, the '__Secure-' prefix must be used for the cookie name. | verification_requirement |
| owasp-asvs:V3.3.2 | Verify that each cookie's 'SameSite' attribute value is set according to the purpose of the cookie, to limit exposure to user interface redress attacks and browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF). | verification_requirement |
| owasp-asvs:V3.3.3 | Verify that cookies have the '__Host-' prefix for the cookie name unless they are explicitly designed to be shared with other hosts. | verification_requirement |
| owasp-asvs:V3.3.4 | Verify that if the value of a cookie is not meant to be accessible to client-side scripts (such as a session token), the cookie must have the 'HttpOnly' attribute set and the same value (e. g. session token) must only be transferred to the client via the 'Set-Cookie' header field. | verification_requirement |
| owasp-asvs:V3.3.5 | Verify that when the application writes a cookie, the cookie name and value length combined are not over 4096 bytes. Overly large cookies will not be stored by the browser and therefore not sent with requests, preventing the user from using application functionality which relies on that cookie. | verification_requirement |
| owasp-asvs:V3.4.1 | Verify that a Strict-Transport-Security header field is included on all responses to enforce an HTTP Strict Transport Security (HSTS) policy. A maximum age of at least 1 year must be defined, and for L2 and up, the policy must apply to all subdomains as well. | verification_requirement |
| owasp-asvs:V3.4.2 | Verify that the Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin header field is a fixed value by the application, or if the Origin HTTP request header field value is used, it is validated against an allowlist of trusted origins. When 'Access-Control-Allow-Origin: *' needs to be used, verify that the response does not include any sensitive information. | verification_requirement |
| owasp-asvs:V3.4.3 | Verify that HTTP responses include a Content-Security-Policy response header field which defines directives to ensure the browser only loads and executes trusted content or resources, in order to limit execution of malicious JavaScript. As a minimum, a global policy must be used which includes the directives object-src 'none' and base-uri 'none' and defines either an allowlist or uses nonces or hashes. For an L3 application, a per-response policy with nonces or hashes must be defined. | verification_requirement |
| owasp-asvs:V3.4.4 | Verify that all HTTP responses contain an 'X-Content-Type-Options: nosniff' header field. This instructs browsers not to use content sniffing and MIME type guessing for the given response, and to require the response's Content-Type header field value to match the destination resource. For example, the response to a request for a style is only accepted if the response's Content-Type is 'text/css'. This also enables the use of the Cross-Origin Read Blocking (CORB) functionality by the browser. | verification_requirement |
| owasp-asvs:V3.4.5 | Verify that the application sets a referrer policy to prevent leakage of technically sensitive data to third-party services via the 'Referer' HTTP request header field. This can be done using the Referrer-Policy HTTP response header field or via HTML element attributes. Sensitive data could include path and query data in the URL, and for internal non-public applications also the hostname. | verification_requirement |
| owasp-asvs:V3.4.6 | Verify that the web application uses the frame-ancestors directive of the Content-Security-Policy header field for every HTTP response to ensure that it cannot be embedded by default and that embedding of specific resources is allowed only when necessary. Note that the X-Frame-Options header field, although supported by browsers, is obsolete and may not be relied upon. | verification_requirement |
| owasp-asvs:V3.4.7 | Verify that the Content-Security-Policy header field specifies a location to report violations. | verification_requirement |
| owasp-asvs:V3.4.8 | Verify that all HTTP responses that initiate a document rendering (such as responses with Content-Type text/html), include the Cross‑Origin‑Opener‑Policy header field with the same-origin directive or the same-origin-allow-popups directive as required. This prevents attacks that abuse shared access to Window objects, such as tabnabbing and frame counting. | verification_requirement |
| owasp-asvs:V3.5.1 | Verify that, if the application does not rely on the CORS preflight mechanism to prevent disallowed cross-origin requests to use sensitive functionality, these requests are validated to ensure they originate from the application itself. This may be done by using and validating anti-forgery tokens or requiring extra HTTP header fields that are not CORS-safelisted request-header fields. This is to defend against browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF). | verification_requirement |
| owasp-asvs:V3.5.2 | Verify that, if the application relies on the CORS preflight mechanism to prevent disallowed cross-origin use of sensitive functionality, it is not possible to call the functionality with a request which does not trigger a CORS-preflight request. This may require checking the values of the 'Origin' and 'Content-Type' request header fields or using an extra header field that is not a CORS-safelisted header-field. | verification_requirement |
| owasp-asvs:V3.5.3 | Verify that HTTP requests to sensitive functionality use appropriate HTTP methods such as POST, PUT, PATCH, or DELETE, and not methods defined by the HTTP specification as "safe" such as HEAD, OPTIONS, or GET. Alternatively, strict validation of the Sec-Fetch-* request header fields can be used to ensure that the request did not originate from an inappropriate cross-origin call, a navigation request, or a resource load (such as an image source) where this is not expected. | verification_requirement |
| owasp-asvs:V3.5.4 | Verify that separate applications are hosted on different hostnames to leverage the restrictions provided by same-origin policy, including how documents or scripts loaded by one origin can interact with resources from another origin and hostname-based restrictions on cookies. | verification_requirement |
| owasp-asvs:V3.5.5 | Verify that messages received by the postMessage interface are discarded if the origin of the message is not trusted, or if the syntax of the message is invalid. | verification_requirement |
| owasp-asvs:V3.5.6 | Verify that JSONP functionality is not enabled anywhere across the application to avoid Cross-Site Script Inclusion (XSSI) attacks. | verification_requirement |
| owasp-asvs:V3.5.7 | Verify that data requiring authorization is not included in script resource responses, like JavaScript files, to prevent Cross-Site Script Inclusion (XSSI) attacks. | verification_requirement |
| owasp-asvs:V3.5.8 | Verify that authenticated resources (such as images, videos, scripts, and other documents) can be loaded or embedded on behalf of the user only when intended. This can be accomplished by strict validation of the Sec-Fetch-* HTTP request header fields to ensure that the request did not originate from an inappropriate cross-origin call, or by setting a restrictive Cross-Origin-Resource-Policy HTTP response header field to instruct the browser to block returned content. | verification_requirement |
| owasp-asvs:V3.6.1 | Verify that client-side assets, such as JavaScript libraries, CSS, or web fonts, are only hosted externally (e.g., on a Content Delivery Network) if the resource is static and versioned and Subresource Integrity (SRI) is used to validate the integrity of the asset. If this is not possible, there should be a documented security decision to justify this for each resource. | verification_requirement |
| owasp-asvs:V3.7.1 | Verify that the application only uses client-side technologies which are still supported and considered secure. Examples of technologies which do not meet this requirement include NSAPI plugins, Flash, Shockwave, ActiveX, Silverlight, NACL, or client-side Java applets. | verification_requirement |
| owasp-asvs:V3.7.2 | Verify that the application will only automatically redirect the user to a different hostname or domain (which is not controlled by the application) where the destination appears on an allowlist. | verification_requirement |
| owasp-asvs:V3.7.3 | Verify that the application shows a notification when the user is being redirected to a URL outside of the application's control, with an option to cancel the navigation. | verification_requirement |
| owasp-asvs:V3.7.4 | Verify that the application's top-level domain (e.g., site.tld) is added to the public preload list for HTTP Strict Transport Security (HSTS). This ensures that the use of TLS for the application is built directly into the main browsers, rather than relying only on the Strict-Transport-Security response header field. | verification_requirement |
| owasp-asvs:V3.7.5 | Verify that the application behaves as documented (such as warning the user or blocking access) if the browser used to access the application does not support the expected security features. | verification_requirement |
| owasp-asvs:V4.1.1 | Verify that every HTTP response with a message body contains a Content-Type header field that matches the actual content of the response, including the charset parameter to specify safe character encoding (e.g., UTF-8, ISO-8859-1) according to IANA Media Types, such as "text/", "/+xml" and "/xml". | verification_requirement |
| owasp-asvs:V4.1.2 | Verify that only user-facing endpoints (intended for manual web-browser access) automatically redirect from HTTP to HTTPS, while other services or endpoints do not implement transparent redirects. This is to avoid a situation where a client is erroneously sending unencrypted HTTP requests, but since the requests are being automatically redirected to HTTPS, the leakage of sensitive data goes undiscovered. | verification_requirement |
| owasp-asvs:V4.1.3 | Verify that any HTTP header field used by the application and set by an intermediary layer, such as a load balancer, a web proxy, or a backend-for-frontend service, cannot be overridden by the end-user. Example headers might include X-Real-IP, X-Forwarded-*, or X-User-ID. | verification_requirement |
| owasp-asvs:V4.1.4 | Verify that only HTTP methods that are explicitly supported by the application or its API (including OPTIONS during preflight requests) can be used and that unused methods are blocked. | verification_requirement |
| owasp-asvs:V4.1.5 | Verify that per-message digital signatures are used to provide additional assurance on top of transport protections for requests or transactions which are highly sensitive or which traverse a number of systems. | verification_requirement |
| owasp-asvs:V4.2.1 | Verify that all application components (including load balancers, firewalls, and application servers) determine boundaries of incoming HTTP messages using the appropriate mechanism for the HTTP version to prevent HTTP request smuggling. In HTTP/1.x, if a Transfer-Encoding header field is present, the Content-Length header must be ignored per RFC 2616. When using HTTP/2 or HTTP/3, if a Content-Length header field is present, the receiver must ensure that it is consistent with the length of the DATA frames. | verification_requirement |
| owasp-asvs:V4.2.2 | Verify that when generating HTTP messages, the Content-Length header field does not conflict with the length of the content as determined by the framing of the HTTP protocol, in order to prevent request smuggling attacks. | verification_requirement |
| owasp-asvs:V4.2.3 | Verify that the application does not send nor accept HTTP/2 or HTTP/3 messages with connection-specific header fields such as Transfer-Encoding to prevent response splitting and header injection attacks. | verification_requirement |
| owasp-asvs:V4.2.4 | Verify that the application only accepts HTTP/2 and HTTP/3 requests where the header fields and values do not contain any CR (\r), LF (\n), or CRLF (\r\n) sequences, to prevent header injection attacks. | verification_requirement |
| owasp-asvs:V4.2.5 | Verify that, if the application (backend or frontend) builds and sends requests, it uses validation, sanitization, or other mechanisms to avoid creating URIs (such as for API calls) or HTTP request header fields (such as Authorization or Cookie), which are too long to be accepted by the receiving component. This could cause a denial of service, such as when sending an overly long request (e.g., a long cookie header field), which results in the server always responding with an error status. | verification_requirement |
| owasp-asvs:V4.3.1 | Verify that a query allowlist, depth limiting, amount limiting, or query cost analysis is used to prevent GraphQL or data layer expression Denial of Service (DoS) as a result of expensive, nested queries. | verification_requirement |
| owasp-asvs:V4.3.2 | Verify that GraphQL introspection queries are disabled in the production environment unless the GraphQL API is meant to be used by other parties. | verification_requirement |
| owasp-asvs:V4.4.1 | Verify that WebSocket over TLS (WSS) is used for all WebSocket connections. | verification_requirement |
| owasp-asvs:V4.4.2 | Verify that, during the initial HTTP WebSocket handshake, the Origin header field is checked against a list of origins allowed for the application. | verification_requirement |
| owasp-asvs:V4.4.3 | Verify that, if the application's standard session management cannot be used, dedicated tokens are being used for this, which comply with the relevant Session Management security requirements. | verification_requirement |
| owasp-asvs:V4.4.4 | Verify that dedicated WebSocket session management tokens are initially obtained or validated through the previously authenticated HTTPS session when transitioning an existing HTTPS session to a WebSocket channel. | verification_requirement |
| owasp-asvs:V5.1.1 | Verify that the documentation defines the permitted file types, expected file extensions, and maximum size (including unpacked size) for each upload feature. Additionally, ensure that the documentation specifies how files are made safe for end-users to download and process, such as how the application behaves when a malicious file is detected. | verification_requirement |
| owasp-asvs:V5.2.1 | Verify that the application will only accept files of a size which it can process without causing a loss of performance or a denial of service attack. | verification_requirement |
| owasp-asvs:V5.2.2 | Verify that when the application accepts a file, either on its own or within an archive such as a zip file, it checks if the file extension matches an expected file extension and validates that the contents correspond to the type represented by the extension. This includes, but is not limited to, checking the initial 'magic bytes', performing image re-writing, and using specialized libraries for file content validation. For L1, this can focus just on files which are used to make specific business or security decisions. For L2 and up, this must apply to all files being accepted. | verification_requirement |
| owasp-asvs:V5.2.3 | Verify that the application checks compressed files (e.g., zip, gz, docx, odt) against maximum allowed uncompressed size and against maximum number of files before uncompressing the file. | verification_requirement |
| owasp-asvs:V5.2.4 | Verify that a file size quota and maximum number of files per user are enforced to ensure that a single user cannot fill up the storage with too many files, or excessively large files. | verification_requirement |
| owasp-asvs:V5.2.5 | Verify that the application does not allow uploading compressed files containing symlinks unless this is specifically required (in which case it will be necessary to enforce an allowlist of the files that can be symlinked to). | verification_requirement |
| owasp-asvs:V5.2.6 | Verify that the application rejects uploaded images with a pixel size larger than the maximum allowed, to prevent pixel flood attacks. | verification_requirement |
| owasp-asvs:V5.3.1 | Verify that files uploaded or generated by untrusted input and stored in a public folder, are not executed as server-side program code when accessed directly with an HTTP request. | verification_requirement |
| owasp-asvs:V5.3.2 | Verify that when the application creates file paths for file operations, instead of user-submitted filenames, it uses internally generated or trusted data, or if user-submitted filenames or file metadata must be used, strict validation and sanitization must be applied. This is to protect against path traversal, local or remote file inclusion (LFI, RFI), and server-side request forgery (SSRF) attacks. | verification_requirement |
| owasp-asvs:V5.3.3 | Verify that server-side file processing, such as file decompression, ignores user-provided path information to prevent vulnerabilities such as zip slip. | verification_requirement |
| owasp-asvs:V5.4.1 | Verify that the application validates or ignores user-submitted filenames, including in a JSON, JSONP, or URL parameter and specifies a filename in the Content-Disposition header field in the response. | verification_requirement |
| owasp-asvs:V5.4.2 | Verify that file names served (e.g., in HTTP response header fields or email attachments) are encoded or sanitized (e.g., following RFC 6266) to preserve document structure and prevent injection attacks. | verification_requirement |
| owasp-asvs:V5.4.3 | Verify that files obtained from untrusted sources are scanned by antivirus scanners to prevent serving of known malicious content. | verification_requirement |
| owasp-asvs:V6.1.1 | Verify that application documentation defines how controls such as rate limiting, anti-automation, and adaptive response, are used to defend against attacks such as credential stuffing and password brute force. The documentation must make clear how these controls are configured and prevent malicious account lockout. | verification_requirement |
| owasp-asvs:V6.1.2 | Verify that a list of context-specific words is documented in order to prevent their use in passwords. The list could include permutations of organization names, product names, system identifiers, project codenames, department or role names, and similar. | verification_requirement |
| owasp-asvs:V6.1.3 | Verify that, if the application includes multiple authentication pathways, these are all documented together with the security controls and authentication strength which must be consistently enforced across them. | verification_requirement |
| owasp-asvs:V6.2.1 | Verify that user set passwords are at least 8 characters in length although a minimum of 15 characters is strongly recommended. | verification_requirement |
| owasp-asvs:V6.2.10 | Verify that a user's password stays valid until it is discovered to be compromised or the user rotates it. The application must not require periodic credential rotation. | verification_requirement |
| owasp-asvs:V6.2.11 | Verify that the documented list of context specific words is used to prevent easy to guess passwords being created. | verification_requirement |
| owasp-asvs:V6.2.12 | Verify that passwords submitted during account registration or password changes are checked against a set of breached passwords. | verification_requirement |
| owasp-asvs:V6.2.2 | Verify that users can change their password. | verification_requirement |
| owasp-asvs:V6.2.3 | Verify that password change functionality requires the user's current and new password. | verification_requirement |
| owasp-asvs:V6.2.4 | Verify that passwords submitted during account registration or password change are checked against an available set of, at least, the top 3000 passwords which match the application's password policy, e.g. minimum length. | verification_requirement |
| owasp-asvs:V6.2.5 | Verify that passwords of any composition can be used, without rules limiting the type of characters permitted. There must be no requirement for a minimum number of upper or lower case characters, numbers, or special characters. | verification_requirement |
| owasp-asvs:V6.2.6 | Verify that password input fields use type=password to mask the entry. Applications may allow the user to temporarily view the entire masked password, or the last typed character of the password. | verification_requirement |
| owasp-asvs:V6.2.7 | Verify that "paste" functionality, browser password helpers, and external password managers are permitted. | verification_requirement |
| owasp-asvs:V6.2.8 | Verify that the application verifies the user's password exactly as received from the user, without any modifications such as truncation or case transformation. | verification_requirement |
| owasp-asvs:V6.2.9 | Verify that passwords of at least 64 characters are permitted. | verification_requirement |
| owasp-asvs:V6.3.1 | Verify that controls to prevent attacks such as credential stuffing and password brute force are implemented according to the application's security documentation. | verification_requirement |
| owasp-asvs:V6.3.2 | Verify that default user accounts (e.g., "root", "admin", or "sa") are not present in the application or are disabled. | verification_requirement |
| owasp-asvs:V6.3.3 | Verify that either a multi-factor authentication mechanism or a combination of single-factor authentication mechanisms, must be used in order to access the application. For L3, one of the factors must be a hardware-based authentication mechanism which provides compromise and impersonation resistance against phishing attacks while verifying the intent to authenticate by requiring a user-initiated action (such as a button press on a FIDO hardware key or a mobile phone). Relaxing any of the considerations in this requirement requires a fully documented rationale and a comprehensive set of mitigating controls. | verification_requirement |
| owasp-asvs:V6.3.4 | Verify that, if the application includes multiple authentication pathways, there are no undocumented pathways and that security controls and authentication strength are enforced consistently. | verification_requirement |
| owasp-asvs:V6.3.5 | Verify that users are notified of suspicious authentication attempts (successful or unsuccessful). This may include authentication attempts from an unusual location or client, partially successful authentication (only one of multiple factors), an authentication attempt after a long period of inactivity or a successful authentication after several unsuccessful attempts. | verification_requirement |
| owasp-asvs:V6.3.6 | Verify that email is not used as either a single-factor or multi-factor authentication mechanism. | verification_requirement |
| owasp-asvs:V6.3.7 | Verify that users are notified after updates to authentication details, such as credential resets or modification of the username or email address. | verification_requirement |
| owasp-asvs:V6.3.8 | Verify that valid users cannot be deduced from failed authentication challenges, such as by basing on error messages, HTTP response codes, or different response times. Registration and forgot password functionality must also have this protection. | verification_requirement |
| owasp-asvs:V6.4.1 | Verify that system generated initial passwords or activation codes are securely randomly generated, follow the existing password policy, and expire after a short period of time or after they are initially used. These initial secrets must not be permitted to become the long term password. | verification_requirement |
| owasp-asvs:V6.4.2 | Verify that password hints or knowledge-based authentication (so-called "secret questions") are not present. | verification_requirement |
| owasp-asvs:V6.4.3 | Verify that a secure process for resetting a forgotten password is implemented, that does not bypass any enabled multi-factor authentication mechanisms. | verification_requirement |
| owasp-asvs:V6.4.4 | Verify that if a multi-factor authentication factor is lost, evidence of identity proofing is performed at the same level as during enrollment. | verification_requirement |
| owasp-asvs:V6.4.5 | Verify that renewal instructions for authentication mechanisms which expire are sent with enough time to be carried out before the old authentication mechanism expires, configuring automated reminders if necessary. | verification_requirement |
| owasp-asvs:V6.4.6 | Verify that administrative users can initiate the password reset process for the user, but that this does not allow them to change or choose the user's password. This prevents a situation where they know the user's password. | verification_requirement |
| owasp-asvs:V6.5.1 | Verify that lookup secrets, out-of-band authentication requests or codes, and time-based one-time passwords (TOTPs) are only successfully usable once. | verification_requirement |
| owasp-asvs:V6.5.2 | Verify that, when being stored in the application's backend, lookup secrets with less than 112 bits of entropy (19 random alphanumeric characters or 34 random digits) are hashed with an approved password storage hashing algorithm that incorporates a 32-bit random salt. A standard hash function can be used if the secret has 112 bits of entropy or more. | verification_requirement |
| owasp-asvs:V6.5.3 | Verify that lookup secrets, out-of-band authentication code, and time-based one-time password seeds, are generated using a Cryptographically Secure Pseudorandom Number Generator (CSPRNG) to avoid predictable values. | verification_requirement |
| owasp-asvs:V6.5.4 | Verify that lookup secrets and out-of-band authentication codes have a minimum of 20 bits of entropy (typically 4 random alphanumeric characters or 6 random digits is sufficient). | verification_requirement |
| owasp-asvs:V6.5.5 | Verify that out-of-band authentication requests, codes, or tokens, as well as time-based one-time passwords (TOTPs) have a defined lifetime. Out of band requests must have a maximum lifetime of 10 minutes and for TOTP a maximum lifetime of 30 seconds. | verification_requirement |
| owasp-asvs:V6.5.6 | Verify that any authentication factor (including physical devices) can be revoked in case of theft or other loss. | verification_requirement |
| owasp-asvs:V6.5.7 | Verify that biometric authentication mechanisms are only used as secondary factors together with either something you have or something you know. | verification_requirement |
| owasp-asvs:V6.5.8 | Verify that time-based one-time passwords (TOTPs) are checked based on a time source from a trusted service and not from an untrusted or client provided time. | verification_requirement |
| owasp-asvs:V6.6.1 | Verify that authentication mechanisms using the Public Switched Telephone Network (PSTN) to deliver One-time Passwords (OTPs) via phone or SMS are offered only when the phone number has previously been validated, alternate stronger methods (such as Time based One-time Passwords) are also offered, and the service provides information on their security risks to users. For L3 applications, phone and SMS must not be available as options. | verification_requirement |
| owasp-asvs:V6.6.2 | Verify that out-of-band authentication requests, codes, or tokens are bound to the original authentication request for which they were generated and are not usable for a previous or subsequent one. | verification_requirement |
| owasp-asvs:V6.6.3 | Verify that a code based out-of-band authentication mechanism is protected against brute force attacks by using rate limiting. Consider also using a code with at least 64 bits of entropy. | verification_requirement |
| owasp-asvs:V6.6.4 | Verify that, where push notifications are used for multi-factor authentication, rate limiting is used to prevent push bombing attacks. Number matching may also mitigate this risk. | verification_requirement |
| owasp-asvs:V6.7.1 | Verify that the certificates used to verify cryptographic authentication assertions are stored in a way protects them from modification. | verification_requirement |
| owasp-asvs:V6.7.2 | Verify that the challenge nonce is at least 64 bits in length, and statistically unique or unique over the lifetime of the cryptographic device. | verification_requirement |
| owasp-asvs:V6.8.1 | Verify that, if the application supports multiple identity providers (IdPs), the user's identity cannot be spoofed via another supported identity provider (eg. by using the same user identifier). The standard mitigation would be for the application to register and identify the user using a combination of the IdP ID (serving as a namespace) and the user's ID in the IdP. | verification_requirement |
| owasp-asvs:V6.8.2 | Verify that the presence and integrity of digital signatures on authentication assertions (for example on JWTs or SAML assertions) are always validated, rejecting any assertions that are unsigned or have invalid signatures. | verification_requirement |
| owasp-asvs:V6.8.3 | Verify that SAML assertions are uniquely processed and used only once within the validity period to prevent replay attacks. | verification_requirement |
| owasp-asvs:V6.8.4 | Verify that, if an application uses a separate Identity Provider (IdP) and expects specific authentication strength, methods, or recentness for specific functions, the application verifies this using the information returned by the IdP. For example, if OIDC is used, this might be achieved by validating ID Token claims such as 'acr', 'amr', and 'auth_time' (if present). If the IdP does not provide this information, the application must have a documented fallback approach that assumes that the minimum strength authentication mechanism was used (for example, single-factor authentication using username and password). | verification_requirement |
| owasp-asvs:V7.1.1 | Verify that the user's session inactivity timeout and absolute maximum session lifetime are documented, are appropriate in combination with other controls, and that the documentation includes justification for any deviations from NIST SP 800-63B re-authentication requirements. | verification_requirement |
| owasp-asvs:V7.1.2 | Verify that the documentation defines how many concurrent (parallel) sessions are allowed for one account as well as the intended behaviors and actions to be taken when the maximum number of active sessions is reached. | verification_requirement |
| owasp-asvs:V7.1.3 | Verify that all systems that create and manage user sessions as part of a federated identity management ecosystem (such as SSO systems) are documented along with controls to coordinate session lifetimes, termination, and any other conditions that require re-authentication. | verification_requirement |
| owasp-asvs:V7.2.1 | Verify that the application performs all session token verification using a trusted, backend service. | verification_requirement |
| owasp-asvs:V7.2.2 | Verify that the application uses either self-contained or reference tokens that are dynamically generated for session management, i.e. not using static API secrets and keys. | verification_requirement |
| owasp-asvs:V7.2.3 | Verify that if reference tokens are used to represent user sessions, they are unique and generated using a cryptographically secure pseudo-random number generator (CSPRNG) and possess at least 128 bits of entropy. | verification_requirement |
| owasp-asvs:V7.2.4 | Verify that the application generates a new session token on user authentication, including re-authentication, and terminates the current session token. | verification_requirement |
| owasp-asvs:V7.3.1 | Verify that there is an inactivity timeout such that re-authentication is enforced according to risk analysis and documented security decisions. | verification_requirement |
| owasp-asvs:V7.3.2 | Verify that there is an absolute maximum session lifetime such that re-authentication is enforced according to risk analysis and documented security decisions. | verification_requirement |
| owasp-asvs:V7.4.1 | Verify that when session termination is triggered (such as logout or expiration), the application disallows any further use of the session. For reference tokens or stateful sessions, this means invalidating the session data at the application backend. Applications using self-contained tokens will need a solution such as maintaining a list of terminated tokens, disallowing tokens produced before a per-user date and time or rotating a per-user signing key. | verification_requirement |
| owasp-asvs:V7.4.2 | Verify that the application terminates all active sessions when a user account is disabled or deleted (such as an employee leaving the company). | verification_requirement |
| owasp-asvs:V7.4.3 | Verify that the application gives the option to terminate all other active sessions after a successful change or removal of any authentication factor (including password change via reset or recovery and, if present, an MFA settings update). | verification_requirement |
| owasp-asvs:V7.4.4 | Verify that all pages that require authentication have easy and visible access to logout functionality. | verification_requirement |
| owasp-asvs:V7.4.5 | Verify that application administrators are able to terminate active sessions for an individual user or for all users. | verification_requirement |
| owasp-asvs:V7.5.1 | Verify that the application requires full re-authentication before allowing modifications to sensitive account attributes which may affect authentication such as email address, phone number, MFA configuration, or other information used in account recovery. | verification_requirement |
| owasp-asvs:V7.5.2 | Verify that users are able to view and (having authenticated again with at least one factor) terminate any or all currently active sessions. | verification_requirement |
| owasp-asvs:V7.5.3 | Verify that the application requires further authentication with at least one factor or secondary verification before performing highly sensitive transactions or operations. | verification_requirement |
| owasp-asvs:V7.6.1 | Verify that session lifetime and termination between Relying Parties (RPs) and Identity Providers (IdPs) behave as documented, requiring re-authentication as necessary such as when the maximum time between IdP authentication events is reached. | verification_requirement |
| owasp-asvs:V7.6.2 | Verify that creation of a session requires either the user's consent or an explicit action, preventing the creation of new application sessions without user interaction. | verification_requirement |
| owasp-asvs:V8.1.1 | Verify that authorization documentation defines rules for restricting function-level and data-specific access based on consumer permissions and resource attributes. | verification_requirement |
| owasp-asvs:V8.1.2 | Verify that authorization documentation defines rules for field-level access restrictions (both read and write) based on consumer permissions and resource attributes. Note that these rules might depend on other attribute values of the relevant data object, such as state or status. | verification_requirement |
| owasp-asvs:V8.1.3 | Verify that the application's documentation defines the environmental and contextual attributes (including but not limited to, time of day, user location, IP address, or device) that are used in the application to make security decisions, including those pertaining to authentication and authorization. | verification_requirement |
| owasp-asvs:V8.1.4 | Verify that authentication and authorization documentation defines how environmental and contextual factors are used in decision-making, in addition to function-level, data-specific, and field-level authorization. This should include the attributes evaluated, thresholds for risk, and actions taken (e.g., allow, challenge, deny, step-up authentication). | verification_requirement |
| owasp-asvs:V8.2.1 | Verify that the application ensures that function-level access is restricted to consumers with explicit permissions. | verification_requirement |
| owasp-asvs:V8.2.2 | Verify that the application ensures that data-specific access is restricted to consumers with explicit permissions to specific data items to mitigate insecure direct object reference (IDOR) and broken object level authorization (BOLA). | verification_requirement |
| owasp-asvs:V8.2.3 | Verify that the application ensures that field-level access is restricted to consumers with explicit permissions to specific fields to mitigate broken object property level authorization (BOPLA). | verification_requirement |
| owasp-asvs:V8.2.4 | Verify that adaptive security controls based on a consumer's environmental and contextual attributes (such as time of day, location, IP address, or device) are implemented for authentication and authorization decisions, as defined in the application's documentation. These controls must be applied when the consumer tries to start a new session and also during an existing session. | verification_requirement |
| owasp-asvs:V8.3.1 | Verify that the application enforces authorization rules at a trusted service layer and doesn't rely on controls that an untrusted consumer could manipulate, such as client-side JavaScript. | verification_requirement |
| owasp-asvs:V8.3.2 | Verify that changes to values on which authorization decisions are made are applied immediately. Where changes cannot be applied immediately, (such as when relying on data in self-contained tokens), there must be mitigating controls to alert when a consumer performs an action when they are no longer authorized to do so and revert the change. Note that this alternative would not mitigate information leakage. | verification_requirement |
| owasp-asvs:V8.3.3 | Verify that access to an object is based on the originating subject's (e.g. consumer's) permissions, not on the permissions of any intermediary or service acting on their behalf. For example, if a consumer calls a web service using a self-contained token for authentication, and the service then requests data from a different service, the second service will use the consumer's token, rather than a machine-to-machine token from the first service, to make permission decisions. | verification_requirement |
| owasp-asvs:V8.4.1 | Verify that multi-tenant applications use cross-tenant controls to ensure consumer operations will never affect tenants with which they do not have permissions to interact. | verification_requirement |
| owasp-asvs:V8.4.2 | Verify that access to administrative interfaces incorporates multiple layers of security, including continuous consumer identity verification, device security posture assessment, and contextual risk analysis, ensuring that network location or trusted endpoints are not the sole factors for authorization even though they may reduce the likelihood of unauthorized access. | verification_requirement |
| owasp-asvs:V9.1.1 | Verify that self-contained tokens are validated using their digital signature or MAC to protect against tampering before accepting the token's contents. | verification_requirement |
| owasp-asvs:V9.1.2 | Verify that only algorithms on an allowlist can be used to create and verify self-contained tokens, for a given context. The allowlist must include the permitted algorithms, ideally only either symmetric or asymmetric algorithms, and must not include the 'None' algorithm. If both symmetric and asymmetric must be supported, additional controls will be needed to prevent key confusion. | verification_requirement |
| owasp-asvs:V9.1.3 | Verify that key material that is used to validate self-contained tokens is from trusted pre-configured sources for the token issuer, preventing attackers from specifying untrusted sources and keys. For JWTs and other JWS structures, headers such as 'jku', 'x5u', and 'jwk' must be validated against an allowlist of trusted sources. | verification_requirement |
| owasp-asvs:V9.2.1 | Verify that, if a validity time span is present in the token data, the token and its content are accepted only if the verification time is within this validity time span. For example, for JWTs, the claims 'nbf' and 'exp' must be verified. | verification_requirement |
| owasp-asvs:V9.2.2 | Verify that the service receiving a token validates the token to be the correct type and is meant for the intended purpose before accepting the token's contents. For example, only access tokens can be accepted for authorization decisions and only ID Tokens can be used for proving user authentication. | verification_requirement |
| owasp-asvs:V9.2.3 | Verify that the service only accepts tokens which are intended for use with that service (audience). For JWTs, this can be achieved by validating the 'aud' claim against an allowlist defined in the service. | verification_requirement |
| owasp-asvs:V9.2.4 | Verify that, if a token issuer uses the same private key for issuing tokens to different audiences, the issued tokens contain an audience restriction that uniquely identifies the intended audiences. This will prevent a token from being reused with an unintended audience. If the audience identifier is dynamically provisioned, the token issuer must validate these audiences in order to make sure that they do not result in audience impersonation. | verification_requirement |

## OWASP GenAI LLM Top 10

| ID | Name | Kind |
| --- | --- | --- |
| owasp-llm:LLM01 | Prompt Injection | risk |
| owasp-llm:LLM02 | Sensitive Information Disclosure | risk |
| owasp-llm:LLM03 | Excessive Agency | risk |
| owasp-llm:LLM04 | Supply Chain | risk |
| owasp-llm:LLM05 | Data and Model Poisoning | risk |
| owasp-llm:LLM06 | Unbounded Consumption | risk |
| owasp-llm:LLM07 | Misinformation | risk |
| owasp-llm:LLM08 | Hidden Context Exposure | risk |
| owasp-llm:LLM09 | Vector and Embedding Weaknesses | risk |
| owasp-llm:LLM10 | Improper Output Handling | risk |

## OWASP Top 10

| ID | Name | Kind |
| --- | --- | --- |
| owasp-web:A01 | Broken Access Control | risk |
| owasp-web:A02 | Security Misconfiguration | risk |
| owasp-web:A03 | Software Supply Chain Failures | risk |
| owasp-web:A04 | Cryptographic Failures | risk |
| owasp-web:A05 | Injection | risk |
| owasp-web:A06 | Insecure Design | risk |
| owasp-web:A07 | Authentication Failures | risk |
| owasp-web:A08 | Software or Data Integrity Failures | risk |
| owasp-web:A09 | Security Logging and Alerting Failures | risk |
| owasp-web:A10 | Mishandling of Exceptional Conditions | risk |

## PCI Data Security Standard

| ID | Name | Kind |
| --- | --- | --- |
| pci-dss:1 | Network safeguards | requirement_area |
| pci-dss:10 | Activity records | requirement_area |
| pci-dss:11 | Security evaluation | requirement_area |
| pci-dss:12 | Security governance | requirement_area |
| pci-dss:2 | Secure configuration | requirement_area |
| pci-dss:3 | Stored account data | requirement_area |
| pci-dss:4 | Transmitted account data | requirement_area |
| pci-dss:5 | Malware defenses | requirement_area |
| pci-dss:6 | Secure software | requirement_area |
| pci-dss:7 | Business access boundaries | requirement_area |
| pci-dss:8 | Identity verification | requirement_area |
| pci-dss:9 | Physical access | requirement_area |

## AICPA Trust Services Criteria (SOC 2)

| ID | Name | Kind |
| --- | --- | --- |
| soc2:availability | Availability | trust_category |
| soc2:confidentiality | Confidentiality | trust_category |
| soc2:privacy | Privacy | trust_category |
| soc2:processing-integrity | Processing integrity | trust_category |
| soc2:security | Security | trust_category |
