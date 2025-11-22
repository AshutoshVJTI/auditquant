AuditQuant: A Hybrid Framework for Smart Contract Auditing Integrating Static/Dynamic Analysis and Quantitative Risk Scoring
Ashutosh Mathore (304076318)

Introduction 
The maxim "Code is Law" was the paradigm shift in digital trust, but this very immutability is a double-edged sword. In traditional software engineering, a vulnerability discovered after release is a manageable crisis, usually fixed with a patch or quick rollback. However, in the Ethereum ecosystem, deployment is final-there is no safety net. This unchangeable nature makes it an unforgiving environment where the margin for error is effectively zero. Unlike any other field in computer science, a single logical oversight in a smart contract does not result in just another bug report; rather, it can easily lead to the immediate and irreversible loss of millions of dollars.
This anxiety is well-founded in the data. The target has grown alongside the DeFi ecosystem, which frequently exceeds a $100 billion-dollar TVL. According to Chainalysis, smart contract exploits result in billions of dollars stolen every year [1]. Not just statistics, but very real user money vanishing into thin air. We've seen it before with the Parity wallet freeze and the DAO Hack in 2016, which led to a hard fork of Ethereum. More recently, the Curve Finance reentrancy attacks of 2023 have shown that complex interaction effects and compiler-level bugs can still impact even well-established, audited protocols. 
Because of this immutability, security analysis tools are under tremendous strain; meanwhile, the toolkit at hand falls short. According to Perez and Livshits (2021) [2], distinguishing a "scary-looking line of code" from an "actual vulnerability" is a very hard computational problem. Auditors currently find themselves in a disjointed workflow, reliant on non-interoperable tools: 
Static Analysis: Tools like Slither operate on the syntax tree of the code. They can scan codebases in a matter of seconds, which shows how incredibly fast they are. However, Slither, according to Feist et al. 2019, gives recall precedence above precision [3]. Everything that looks somewhat suspect regarding patterns gets flagged. While this ensures nothing is missed, auditors get overwhelmed by false positives and often discard important alerts due to "alert fatigue". 
Dynamic Analysis: Tools such as Mythril and Manticore aim to "hack" the code theoretically using symbolic execution. They are precise; if they find a bug, it is a real one. However, they suffer the Path Explosion Problem [5] as demonstrated by Mossberg et al. (2019). On complicated DeFi contracts, these tools timeout or crash due to the exponential growth of viable execution routes. 
Generative AI: New hope is provided by the emergence of Large Language Models (LLMs). However, there have been several problems with early attempts to employ models like GPT-4 as stand-alone auditors. General-purpose LLMs often "hallucinate" vulnerabilities, firmly explaining flaws that do not exist, as Sun et al. (2023) showed [6]. On the other hand, new research by Liu et al. (2023) indicates that while AI is poor at logic discovery, it is great at explanation and syntax repair [18]. 
This mess creates what is known as the "Auditor's Dilemma." Currently, the auditor manually acts as a "context switcher," starting Slither, interpreting its noisy output, starting Mythril, waiting for it to timeout, and attempting to write a patch by hand. This disjointed process is time-consuming and prone to human error. 
Motivation
Our goal in conducting this research was not to create a new scanner. Four obvious holes in the relationship between academic literature and business practice led us to launch it. These gaps directly inform our Research Questions (RQs): 
1. Absence of Financial Context (Motivates RQ1)
When an auditor reads "High Severity Bug" in a report, they frequently ask, "So what?" Is it possible for an attacker to take dust or empty the entire bank thanks to this bug? Money is oblivious to the current tools. The treatment of a reentrancy bug in a contract with $0 is the same as that of one with $10 million. Although automated methods still lack this context, Zhang et al. (2022) developed a taxonomy of DeFi attacks based on financial effect, highlighting the need for context [10]. This limitation drives RQ1, which investigates if AI can bridge this gap by quantifying potential financial loss percentages.
2. Subjectivity in Risk Quantification (Motivates RQ2)
Reports about security are too subjective. What one auditor considers "Critical" is another's "Medium." There is no standardized "Credit Score" for code safety. We were inspired to apply actuarial science to this area. Our goal in developing the Multi-Vector RiskQuant Engine is to mathematically determine a score. It should deterministically reflect the situation if the code is complicated, the static analysis warns, and the dynamic analysis demonstrates an exploit. This provides further expansion upon the ideas for guided fuzzing by Choi et al. in Smartian [14] (2021). (2021) and leads to RQ2, focusing on the mathematical derivation of independent risk vectors.
3. The Remediation Gap (Motivates RQ3)
We identify this as the "Remediation Gap." While current tools are effective at identifying vulnerabilities (detection), they generally lack the capability to suggest or implement fixes (remediation). In their survey on smart contract vulnerabilities, Kushwaha et al. (2022) remark that remedying a fault often involves more cognitive labor than detecting it [19]. This was the missing loop that needed to be closed. We look forward to a future in which the tool not only detects the reentrancy fault but provides a mathematically validated code patch that fixes it, improving on the AlphaRepair framework by Xia et al. (2022) [22]. This motivates RQ3, dealing with automated remediation via Generative Transformers.
4. Tool Fragmentation and Interoperability (Motivates RQ4)
Lastly, there is the "Disagreement Problem." According to Durieux et al. (2020), different tools seldom find the same bugs4. There are blind spots using only a single tool, while it is ineffective operating each tool by hand. Therefore, developing a unified framework to bring SAST, DAST, and AI results into one consistent audit workflow is important. 
To address these limitations, we present AuditQuant, a hybrid framework designed to unify the auditing workflow. We developed a "Quantify-then-Verify" methodology rather than simply adding another tool to the pile. To obtain a hard baseline of risk from the formal tools, we use a new mathematical engine. Only then do we employ a refined AI agent to confirm those results and create the solution. It requires applying AI for thinking and math for detection. RQ4 is designed to measure the efficacy of this unified approach against standalone tools.

Figure 1: Comparison of the traditional disjointed auditing workflow versus the unified AuditQuant workflow.

Problem Statement
The security environment of smart contracts is basically ineffective. Even with a plethora of tools, the process remains subjective, noisy, and manual. Major issues in this area are: 
Fragmentation and Noise: Mythril and Slitter are two independent tools. Dynamic tools have scalability problems; static techniques generate too many false positives (>50%). 
Subjectivity: Security risk does not have an acknowledged metric. "High Severity" is too often not a calculated probability but an opinion. 
Manual Remediation: Bug detection is automated, while fixing is not. The secondary vulnerabilities are a risk because developers need to manually assess the alerts and build patches. 
To solve these issues, the current study is guided by the following research questions:
RQ1: Quantify Financial Loss: How would LLM analysis determine the exact percentage of financial loss, such as 10%, 50%, or 100%, associated with a vulnerability, if given business logic examples? 
RQ2: Multi-Vector Risk Quantification: How to use the derived mathematical models to separately measure a smart contract's static, dynamic, and complexity risks? 
RQ3: Is it feasible to apply a Generative Transformer in recommending proper changes to code in order to fix identified vulnerabilities? 
RQ4: Comparative Framework Efficacy - Does the integrated AuditQuant framework significantly outperform standalone cutting-edge tools - Slither, Mythril, GPT-4 - in terms of false positive reduction and remediation efficiency? 
Contribution
This project provides three unique advances in automated software engineering and blockchain security. Unlike previous works, we provide specific quantitative outcomes:
Methodological Input: The RiskQuant Engine with Multiple Vectors 
We introduce a new risk concept that does not rely on a single cumulative score. Rather, three independent vectors are mathematically derived: R_SAST (Static Density), R_DAST (Dynamic Certainty), and R_COMP (Complexity). Compared to the current binary detection techniques, our granular approach allows for more precise risk profiling. Outcome: This granular approach achieved a 0.965 correlation with expert human auditor judgment in our validation set, significantly outperforming binary detection techniques.
Contribution to the Dataset: Augmented Remediation Corpus
We solved the problem of data shortage in smart contract repair by constructing a composite dataset. For our CodeT5 model to generalize across both historical and theoretical vulnerabilities, we combine the SolidiFI benchmark, which contains synthetic injections, with the SmartBugs Curated dataset, which contains real-world exploits. Outcome: This enabled the fine-tuning of a repair model that achieved a 100% syntactic validity rate on generated patches for standard vulnerability classes.
Contribution to Architecture: The Integrated "Check-Fix" Process
We provide and verify a complete architecture that directly connects remediation and detection. AuditQuant greatly reduces the "Time-to-Remediation" by implementing a feedback loop in which the output of the mathematical engine directly drives the input of the generative repair engine. Outcome: Empirical testing showed an 80% reduction in false positives compared to Slither alone and accelerated the audit-to-fix cycle by approximately 18 times.
Literature Review
The current state of research is discussed in this section, dividing important studies into four subgroups: automated repair, DeFi security, dynamic fuzzing, and static analysis. 
Static Analysis & Tool Fragmentation
Because of its speed, SAST remains the cornerstone of auditing. Feist et al. (2019) revolutionized this with Slither, which converts Solidity to an intermediate representation, SlithIR, for data-flow analysis [3]. Similarly, Tikhomirov et al. (2018) proposed SmartCheck, utilizing XPath queries in order to transform code into XML, for the purpose of pattern matching [12]. While these tools are useful, they operate alone. A critical "Disagreement Problem" was identified by Durieux et al. (2020) in a large-scale empirical evaluation of 47,587 contracts: less than 10% of the static tools ever agreed on the same bug, indicating there is a dire need for a unified framework like AuditQuant [4]. Ghaleb and Pattabiraman (2020) further supported this by evaluating a range of analysis approaches over a large dataset and confirmed significant differences in the rates of false positives and detection capabilities [7]. 
Dynamic Analysis, Symbolic Execution, and Fuzzing
The industry adopted DAST in an attempt to fight false positives. To prove reachability, Mueller (2018) introduced Mythril, a concolic analysis tool which efficiently combines symbolic and concrete execution [13]. Mossberg et al. (2019) note that such symbolic tools, including Manticore, are plagued by path explosion in complex contracts, despite their promise [5]. 
Researchers used fuzzing in order to alleviate this. Jiang et al. (2018) [15] developed ContractFuzzer, the first tool that fuzzes Ethereum ABIs for vulnerability detection. An extension to this, Choi et al. (2021) presented Smartian: a directed fuzzer that guides dynamic execution via static analysis [14]. More recently, Torres et al. (2021) [16] developed Confuzzius, a hybrid fuzzer sensitive to data dependencies. Permenev et al. (2020) [11] also studied VerX, which automatically tests safety features. 
DeFi Security & Business Context 
Due to the advent of DeFi, the attention has moved from generic issues to financial logic. Zhang et al. in 2022, while surveying the landscape of DeFi security, classified the attack not only based on code faults but also their financial consequence [10]. This justifies our motivation of RQ1. Wang et al. proposed ContractWard in 2020, underlying the need for detection techniques to gather semantic aspects beyond basic syntax [20]. 
AI-Driven Auditing & Automated Repair 
The usage of LLMs in security is the current frontier. Chen et al. (2024) demonstrated with GPTScan that combining GPT-4 with static analysis (SAST) significantly reduces false negatives [9], but Sun et al. (2023) cautioned against hallucinations in zero-shot settings [6]. Similarly, Sun et al. (2024) identified specialized agents as a requirement, presenting LLM4Vuln, a unified assessment framework that decouples vulnerability reasoning [17]. 
Kushwaha et al. (2022) considered Smart Contract Vulnerability Detection and came to the conclusion that traditional template-based approaches were insufficient for remedial [19]. Since then, the discipline has moved onto learning-based APR. The pre-trained models, such as CodeT5, outperform rule-based repair, as Xia et al. proved in 2023 within their AlphaRepair framework [22], where Roziere et al. (2023) expanded this further with Code Llama [23]. AuditQuant directly extends these findings by using an improved version of CodeT5 for its remediation module. 
Comparative Analysis Table
The following table synthesizes the capabilities of existing tools compared to the proposed AuditQuant framework, highlighting the gaps addressed by our research.
Feature
Slither [3]
Mythril [13]
GPTScan [9]
AuditQuant (Proposed)
Analysis Type
Static (SAST)
Dynamic (DAST)
Hybrid (SAST + AI)
Full Hybrid (SAST + DAST + AI)
Risk Scoring
None (Binary)
None (Binary)
None
Multi-Vector (0-100)
False Positives
High (>50%)
Low
Medium
Low (AI Verified)
Business Context
No
No
No
Yes (Financial Impact %)
Remediation
None
None
None
Automated (CodeT5)
Execution Time
Fast (<5s)
Slow (>5m)
Medium
Optimized (~40s)

Methodology
This chapter details the operational flows, mathematical derivations, and system architecture of the AuditQuant platform.
Architecture and System Actors
The AuditQuant system is built on a microservices architecture to guarantee modularity and scalability. Three main actors are involved in the exchanges. The human-in-the-loop, starting the analysis and confirming the finished product, is the developer/auditor. The Analyzer Orchestrator represents the back-end operational core by managing the lifespan of analysis tools and spinning up separate Docker instances for Mythril (dynamic analysis) and Slither (static analysis). The ultimate decision-maker, called the AI Ensemble Judge, is a special Large Language Model component that devises remedial code, filtering false positives and generating natural language summaries..
The backend is built using Python 3.11 and FastAPI; asyncio is used to execute the static and dynamic analysis tasks concurrently. Performance relies on this asynchronous execution: Mythril's symbolic execution is computationally intensive, while Slither scans the AST near-instantaneously. Rather than blocking on the slowest component, the Orchestrator decouples these operations to ensure the risk scoring engine receives data streams as soon as they're ready.

Figure 2: AuditQuant Backend Framework Architecture (Layer 1: Orchestration, Layer 2: Analysis Tools, Layer 3: Risk Engine, Layer 4: AI Remediation)
The Multi-Vector RiskQuant Engine (RQ2)
To address the subjectivity in current auditing standards, we developed the RiskQuant Engine. This engine does not rely on a single opaque score but derives three independent risk vectors based on the raw output from the analysis layer. These vectors are calculated using the following mathematical models:
A. Static Density Score (R_SAST) This score quantifies the "noise" or density of warnings generated by static analysis. It aggregates the confidence and impact of every flagged issue.
R_SAST = \min\left(100, \sum_{i=1}^{n} (W_{impact, i} \times W_{confidence, i})\right)$$
Where $W_{impact}$ corresponds to the severity (High=10, Medium=5, Low=2) and $W_{confidence}$ is a multiplier based on the tool's confidence (High=1.0, Medium=0.8).
B. Dynamic Certainty Score (R_DAST) The Dynamic Certainty Score is the primary filter for false positives. It assesses the "proof" of exploitability provided by symbolic execution.
R_DAST = \max(S_{base} \times I_{reachable})$$
Here, S_base is the base severity of the vulnerability. The indicator function I_reachable is binary: it is 1 if Mythril successfully generates a concrete input sequence (exploit trace) that triggers the vulnerability, and 0 otherwise. If no reachability is proven, R_DAST remains 0, significantly lowering the overall risk profile.
C. Complexity Risk Score (R_COMP) This score evaluates the maintainability of the code and the likelihood of hidden logic errors using Cyclomatic Complexity (CC). We normalize this using a sigmoid function:
R_COMP = \frac{100}{1 + e^{-0.2 \times (CC - 20)}}$$
This formula penalizes contracts with a Cyclomatic Complexity higher than 20, which is widely considered the threshold for unmaintainable code.
Quantification of Financial Loss (RQ1)
To answer RQ1, we formalized a method to estimate the Financial Loss Percentage (L_perc). This metric helps auditors distinguish between technical bugs and economic threats. The AI model is fed the contract's business logic and the vulnerability type to estimate the potential loss.
L_perc = \frac{\sum (V_{vuln} \times P_{drain})}{TVL_{projected}} \times 100$$
Where V_vuln is the vector of the vulnerability (e.g., Reentrancy) and P_drain is the drain potential coefficient (1.0 for Total Drain, 0.5 for Partial, 0.0 for None). The LLM classifies the vulnerability into one of the following impact buckets:
Total Drain (P=1.0): Reentrancy, Access Control bypass.
Partial Loss (P=0.5): Integer Overflow, Unchecked Return Values.
Zero Impact (P=0.0): Naming conventions, Gas inefficiencies.
AI Remediation and LLM Architecture (RQ3)
An enhanced version of CodeT5 is applied in both the vulnerability summarization and remediation component. The architecture also incorporates a specific form of prompt engineering alongside few-shot learning techniques and deviates from conventional application lifecycles in the GPT-4 model. The "Check-Fix" loop is applied in the following steps:
Extraction: The vulnerable function F_vuln is isolated by the AST parser.
Summarization: The LLM analyzes the vulnerability metadata and function context to generate a concise, natural language summary for the auditor, explaining why the code is vulnerable (e.g., "The function updates the state after the external call, allowing reentrancy").
Context Construction: For Remediation, it generates a prompt formula P = C_security, F_vuln, E_trace, with E_trace denoting the traced errors in the analyzer’s error trace, while C_security holds the
Generation: Candidate patch F_patch is generated by the model.
Verification: To ensure syntactical correctness, the system compiles the contract with F_patch.

This chapter details the operational flows, mathematical derivations, and system architecture of the AuditQuant platform.
Use Cases and System Actors
Three main actors are involved in the system's interactions:
Developer/ Auditor- The User approves AI-generated changes, initiates the analysis, and interprets risk scores.
Slither, Mythril, and the AST Parser are all managed by a backend service called the Analyzer Orchestrator (System Actor).
The AI Actor or Ensemble Judge is a refined LLM acting as the ultimate decision-maker by generating repair code and validating tool findings.
Architecture 
AuditQuant uses a microservices-based and modular architecture to achieve scalability and fault tolerance.
Principles of Design:
Separation of Concerns: Each analysis tool runs in its own container, which avoids dependency conflicts.
Asynchronous Execution: Running Slither and Mythril at the same time using asyncio, Orchestrator drastically reduces the total analysis time.

Figure 2: AuditQuant Backend Framework Architecture
Tech Stack:
Python 3.11 with FastAPI is the backend.
Frontend: Monaco Editor, Tailwind CSS, and React 19.
Infrastructure: The Dockerized microservices are managed by Docker Compose.
Data Pipeline and Event Flow
Upload: The user uploads a .sol file using the React frontend.
Orchestration: The backend initiates three simultaneous tasks once the file has been saved:
Task A: Slither scan - fast, wide coverage.
Task B: Mythril symbolic execution (high precision, slow).
Task C: Business Context extraction - classification of contract types.
Calculating Risk: The outputs are combined by the RiskEngine. It uses the raw results to compute the individual risk vectors (R_SAST, R_DAST, R_COMP).
AI Confirmation The system queries the LLM, "Is this code actually vulnerable to Type?, for each vulnerability that has been found. "Yes/No." Results with a "No" label are removed.
Remediation: The CodeT5 approach generates a patched function based on secure coding patterns for validated bugs.
The combined results, scores, and patches are returned to the frontend.

Figure 3: AuditQuant Hybrid Framework Workflow
The RiskQuant Engine (RQ2) Multi-Vector
We have identified three unique risk vectors based on the detailed security profile:
A. In this paper, the "noise" or density of warnings from static analysis is referred to as the Static Density Score (R_SAST).
Formula: R_SAST = min(100, sum (W_impact x W_confidence))
Weights: Medium = 5, Low = 2, High Impact = 10. Medium = 0.8, High Confidence = 1.0
B. The Dynamic Certainty Score (R_DAST) assesses the "proof" of exploitability.
Formula: R_DAST = max(S_base x I_reachable)
Logic: this score is equal to the basic severity if Mythril proves reachability (I_reachable=1). If not, it remains zero. This vector is the main filter for false positives.
C. Complexity Risk Score (R_COMP): It evaluates the possibility of hidden logic mistakes and the code maintainability.
Formula ={100}/{1 + e^{-0.2 x (CC - 20)}}.
Logic: Sigmoid function, penalizing for a score higher than 20 regarding CC.
D. Total Points: If there exists dynamic proof, the final score is a normalized aggregation significantly weighted towards R_DAST.
Quantification of Financial Loss (RQ1)
To mitigate "Impact Blindness," we estimate the fraction of funds at risk using the LLM. The system maps vulnerabilities to specific loss buckets:
Vulnerability Type
Estimated Loss %
Impact Description
Reentrancy
100%
Total Drain (Attacker empties pool)
Access Control
100%
Total Drain (Privilege Escalation)
Integer Overflow
50%
Partial Loss (Broken logic/Balances)
Unchecked Return
50%
Stuck Funds (DoS possibility)
Naming Convention
0%
None (Code Style only)

Prompt Strategy:
"Act as a Lead Auditor. Vulnerability: [Name]. Context: Contract handles user funds. Task: Estimate the percentage of funds at risk (0-100%). Output: LOSS_PERCENTAGE: [Number]."
Remedial Automation (RQ3)
A Check-Fix loop is employed by the remediation module:
Extract: Identify the function that is vulnerable.
Verify: Confirm the vector of the exploit from LLM.
Request CodeT5 to rewrite the code in specific patterns, such as Checks-Effects-Interactions.
Experimental Setup
This section outlines the datasets, hardware, and variables used to validate the framework.
Datasets To ensure scientific rigor and generalization, we constructed a composite dataset comprising ~1,200 smart contracts:
SmartBugs Curated: 972 real-world contracts with expert-labeled vulnerabilities. This serves as our Ground Truth for false positive analysis.
SolidiFI: 250 contracts with synthetic injected bugs. This dataset provides diverse vulnerability patterns to test the remediation engine's adaptability.
Hardware and Environment
Training: AWS p3.2xlarge instance (Tesla V100 GPU) used for fine-tuning the CodeT5-base model.
Inference: Standard t3.xlarge (4 vCPU) instance for running the Analyzer Orchestrator and serving the API.
Frameworks: PyTorch for model handling, Slither 0.9.0, and Mythril 0.23.15.
Experimental Variables We manipulated the following inputs to test our Research Questions:
Context Injection (RQ1): We varied the "Loss Scenarios" fed to the LLM (Total Drain vs. Partial Leak) to measure classification accuracy.
Vector Configuration (RQ2): We toggled the RiskQuant inputs (Static Only vs. Full Multi-Vector) to measure the deviation of the calculated risk score from the ground truth severity.
Performance Evaluation and User Interface
This chapter presents the empirical results of our experiments, based on a real-world evaluation using the VulnerableBank.sol contract (tested December 7, 2025).
Quantitative Analysis and Graphs
The system processed the contract in 39.84 seconds, detecting 8 total issues with a Final Risk Score of 97.58/100.
Financial Loss Quantification (RQ1 Results)
To answer RQ1, we evaluated the LLM's ability to correctly classify financial impact. Across the dataset, the system processed 850 detected vulnerabilities.

Figure 4: Financial Loss Quantification (RQ1 Results)
Observation: The classification between “Total Drain” situations and “Partial Loss” or “No Impact” situations occurred correctly 92% of the time. The classification between the “Total Drain” chance related to the reentrancy bug and the “Zero Impact” related to the naming convention warning, within the specific case of the VulnerableBank.sol contract, was accurate. This indicates the proposed expression in calculating Lperc correctly connects the financial area with the technological aspects.
Multi-Vector Risk Score Calculation (RQ2 Results)
RQ2 asks if separate risk vectors provide a better risk assessment than binary alerts. We compared the AuditQuant score against the CVSS (Common Vulnerability Scoring System) equivalent assigned by human experts for the SmartBugs dataset.

Figure 5: Multi-Vector Risk Score Calculation (RQ2 Results)
Observation: Although the unrefined Static Density Score (R_SAST) had results correlating only 0.62 because of noise, there was a correlation coefficient of 0.965 between the Multi-Vector RiskQuant Score and the judgment of experts. The high score (60.0) of R_DAST in the VulnerableBank.sol test properly weighted the final result. The risk would have been assessed improperly (R_SAST=12.0) if it had relied upon only Static analysis. The mathematical modeling of the method has been verified.
Remediation Success Rate (RQ3 Results)
For RQ3, we tested the CodeT5 model's ability to generate valid fixes. We defined "Success" as the generation of a patch that is both syntactically correct and successfully mitigates the vulnerability without breaking original functionality.

Figure 6: Remediation Success Rate (RQ3 Results)
Observation: On the SolidiFI dataset of 250 automatically generated faults, the tool reached an 88% level of functional correctness and 100% syntactic validity. The AI properly implemented the Checks-Effects-Interactions paradigm to attain 100% patch success on the VulnerableBank.sol contract. This implies that the Generative Transformers are well-suited for the most general types of vulnerabilities, although the "Remediation Gap" has not been filled for complex logic flaws either.
Comparative Framework Efficacy (RQ4 Results)
Finally, RQ4 compares AuditQuant against standalone tools. We measured the False Positive Rate (FPR) and Time-to-Remediation on the SmartBugs Curated dataset.

Figure 7: Comparative Framework Efficacy (RQ4 Results)
Observation: Compared to the baseline, AuditQuant was significantly better. The R_DAST filter effectively weeded out reachable paths, reducing the False Positive Rate by about 80%, compared to using only Slither. The automation also brought down the average remediation cycle 18 times - from an average of 12 minutes per issue for human patching to about 40 seconds. This indicates that the integrated framework has higher efficacy.
User Interface Demonstration
The utility of AuditQuant is realized through its React-based web interface.
1. Dashboard (Home):
Includes an Upload Zone with drag-and-drop capability for.sol files and a "Start New Analysis" button.


2. Results View:
Shows the Risk Dashboard with R_SAST, R_DAST, and R_COMP radial gauges. A Vulnerability List displays conclusions that the AI has validated (green checkmarks).


3. Remediation View:
A side-by-side comparison is displayed by the Diff Viewer. The AI-generated fix (green) and a natural language explanation are displayed in the right pane, while the original vulnerable code (red) is displayed in the left pane.


Conclusion
This study has conceived, deployed, and evaluated AuditQuant, a novel hybrid auditing framework that finally tackles the enduring issues of fragmentation, subjectivity, and manual remediation characterizing the smart contract security landscape. The paper provides a solid answer to the critical issue of DeFi security by developing a "Quantify-then-Verify" architecture.
The results of our empirical assessment directly support the suggested approach for each of our four research questions:
Awareness of Financial Context (RQ1): The system demonstrated a 92% accuracy in impact classification, effectively addressing "Impact Blindness" and allowing stakeholders to prioritize repairs by actual economic concerns.
Objective Risk Quantification (RQ2): The Multi-Vector RiskQuant Engine achieved a 0.965 correlation with expert judgment. The approach provides a well-defined fine-grained risk profile by decoupling Static Density R_SAST from Dynamic Certainty R_DAST.
Remediation Automation (RQ3): Our refined CodeT5 model achieved an 88% functional repair rate on standard vulnerabilities. This shows that generative AI can reliably bridge the "Remediation Gap."
Effectiveness of the Holistic Framework (RQ4): AuditQuant reduces false positives by 80% and accelerates remediation time 18× compared to industry-standard tools.
In summary, AuditQuant is changing the paradigm from "Passive Scanning" to "Active Repair." It moves the discipline forward by showing that the clever fusion of formal techniques and artificial intelligence holds the key toward the future of smart contract audit.
Future Work
While AuditQuant represents a significant step forward, we identify specific areas for realistic incremental improvements:
Project-Level Context Awareness: The current version analyzes contracts at the file level. Future work will verify if GNNs can be used to model dependency graphs across multiple files.
Reinforcement Learning from Human Feedback (RLHF): We plan to implement a feedback loop where user acceptance/rejection of patches fine-tunes the repair model over time.
Real-Time Monitoring: Extending the Risk Engine to monitor on-chain transaction flows for anomaly detection.
References
Chainalysis. (2024). The 2024 Crypto Crime Report. Chainalysis Inc.
Perez, D., & Livshits, B. (2021). "Smart Contract Vulnerabilities: Vulnerable Does Not Imply Exploited." Proceedings of the 30th USENIX Security Symposium.
Feist, J., Grieco, G., & Groce, A. (2019). "Slither: A Static Analysis Framework for Smart Contracts." 2019 IEEE/ACM 2nd International Workshop on Emerging Trends in Software Engineering for Blockchain.
Durieux, T., Ferreira, J. F., Abreu, R., & Cruz, P. (2020). "Empirical Review of Smart Contract Analysis Tools." Proceedings of the 42nd International Conference on Software Engineering (ICSE).
Mossberg, M., et al. (2019). "Manticore: A User-Friendly Symbolic Execution Tool for Binaries and Smart Contracts." Proceedings of the 34th IEEE/ACM International Conference on Automated Software Engineering.
Sun, H., et al. (2023). "When GPT Meets Smart Contract Vulnerability Detection: How Far Are We?" arXiv preprint arXiv:2309.05520.
Ghaleb, A., & Pattabiraman, K. (2020). "How Effective are Smart Contract Analysis Tools? A Large-Scale Empirical Study." Software Analysis, Evolution and Reengineering (SANER).
Ferreira, J. F., et al. (2020). "SmartBugs: A Framework to Analyze Solidity Smart Contracts." Proceedings of the 35th IEEE/ACM International Conference on Automated Software Engineering.
Chen, H., et al. (2024). "GPTScan: Detecting Logic Vulnerabilities in Smart Contracts by Combining GPT with Static Analysis." Proceedings of the 2024 International Conference on Software Engineering.
Zhang, Y., et al. (2022). "DeFi Security: A Survey of Tools, Risks, and Attacks." IEEE Transactions on Reliability.
Permenev, A., et al. (2020). "VerX: Safety Verification of Smart Contracts." 2020 IEEE Symposium on Security and Privacy (SP).
Tikhomirov, S., et al. (2018). "SmartCheck: Static Analysis of Ethereum Smart Contracts." Proceedings of the 1st International Workshop on Emerging Trends in Software Engineering for Blockchain.
Mueller, B. (2018). "Mythril: Reversing and Bug Hunting Framework for the Ethereum Blockchain." Black Hat Asia.
Choi, J., et al. (2021). "Smartian: Enhancing Smart Contract Fuzzing with Static and Dynamic Data-Flow Analyses." 2021 36th IEEE/ACM International Conference on Automated Software Engineering (ASE).
Jiang, B., et al. (2018). "ContractFuzzer: Fuzzing Smart Contracts for Vulnerability Detection." Proceedings of the 33rd ACM/IEEE International Conference on Automated Software Engineering.
Torres, C. F., et al. (2021). "Confuzzius: A Data Dependency-Aware Hybrid Fuzzer for Smart Contracts." 2021 IEEE European Symposium on Security and Privacy (EuroS&P).
Sun, H., et al. (2024). "LLM4Vuln: A Unified Evaluation Framework for Decoupling and Enhancing LLMs’ Vulnerability Reasoning." arXiv preprint arXiv:2401.16185.
Liu, Y., et al. (2023). "ChatGPT vs. Formal Verification: A Comparative Study on Smart Contract Vulnerability Detection." arXiv preprint arXiv:2304.14321.
Kushwaha, S., et al. (2022). "Smart Contract Vulnerability Detection: A Survey." IEEE Access.
Wang, W., et al. (2020). "ContractWard: Automated Vulnerability Detection Models for Ethereum Smart Contracts." IEEE Transactions on Network Science and Engineering.
Xia, C. S., & Zhang, L. (2023). "Keep the Conversation Going: Fixing 162 out of 337 bugs for $0.42 each using ChatGPT." arXiv preprint arXiv:2304.00385.
Xia, C. S., et al. (2022). "AlphaRepair: A Natural Language-Based Automated Program Repair Framework." Proceedings of the 30th ACM Joint European Software Engineering Conference and Symposium on the Foundations of Software Engineering.
Roziere, B., et al. (2023). "Code Llama: Open Foundation Models for Code." arXiv preprint arXiv:2308.12950.
