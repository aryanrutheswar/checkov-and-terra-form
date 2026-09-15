import React, { useState } from 'react';
import { 
  FileText, 
  HelpCircle, 
  Terminal, 
  Layers, 
  ShieldCheck, 
  ChevronDown, 
  ChevronUp, 
  Copy, 
  Check, 
  BookOpen, 
  ShieldAlert,
  GitBranch,
  Code2,
  Server
} from 'lucide-react';

export const DocumentationView: React.FC = () => {
  const [openFaq, setOpenFaq] = useState<number | null>(0);
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);

  const demoCommands = [
    {
      title: "Step 1: Test Insecure Baseline (Security Gate Fails)",
      cmd: "powershell -ExecutionPolicy Bypass -File .\\scripts\\run_scans.ps1 -Target 'vulnerable'",
      desc: "Executes Checkov on vulnerable code. Flags 39 violations, exits with code 1, and halts the pipeline."
    },
    {
      title: "Step 2: Test Remediated Architecture (Security Gate Passes)",
      cmd: "powershell -ExecutionPolicy Bypass -File .\\scripts\\run_scans.ps1 -Target 'remediated'",
      desc: "Executes Checkov on hardened code. 112 checks pass, exits with code 0, and unlocks Terraform Validate & Plan."
    },
    {
      title: "Step 3: All-in-One Live College Presentation Walkthrough",
      cmd: "powershell -ExecutionPolicy Bypass -File .\\scripts\\demo_walkthrough.ps1",
      desc: "Sequentially walks through the entire 5-stage live demo sequence in color."
    },
    {
      title: "Step 4: Start FastAPI Backend Service",
      cmd: "python -m uvicorn backend.main:app --reload --port 8000",
      desc: "Runs the local Python REST API scanner server connecting Checkov to the dashboard."
    }
  ];

  const coreConcepts = [
    {
      icon: Server,
      title: "What is Infrastructure as Code (IaC)?",
      summary: "IaC is the practice of managing and provisioning computing infrastructure (servers, networks, databases, storage) through machine-readable definition files rather than manual physical hardware configuration or interactive web console clicks."
    },
    {
      icon: Code2,
      title: "What is Terraform?",
      summary: "Terraform by HashiCorp is an open-source declarative IaC tool that allows cloud engineers to write HashiCorp Configuration Language (HCL) manifests defining cloud resources. It computes execution graphs and reconciles desired state against live cloud providers."
    },
    {
      icon: ShieldCheck,
      title: "What is Checkov?",
      summary: "Checkov is a static code analysis engine by Bridgecrew/Prisma Cloud designed specifically for Infrastructure as Code. It parses HCL into an Abstract Syntax Tree (AST), builds a Directed Acyclic Graph (DAG), and evaluates over 1,000 CIS benchmarks and custom policies offline."
    },
    {
      icon: ShieldAlert,
      title: "Why is IaC Security Important?",
      summary: "Cloud misconfigurations (like public S3 buckets, open SSH ports, and wildcard IAM roles) cause over 80% of enterprise cloud breaches. Static IaC security shifts protection left into the developer's pull request, preventing vulnerabilities before infrastructure is ever provisioned."
    },
    {
      icon: Layers,
      title: "How Does the Static Scan Work?",
      summary: "Checkov parses HCL into an AST and resolves resource relationships (e.g. security group rules attached to EC2 or RDS). It checks attributes against declarative YAML and procedural Python rules without requiring real AWS credentials or cloud deployments."
    },
    {
      icon: GitBranch,
      title: "What Does the Security Gate Mean?",
      summary: "A Security Gate is an automated policy enforcer configured with thresholds (defined in security.config.json). If violations matching blocking severities (CRITICAL, HIGH) are found, the scanner exits with code 1 ('GATE: BLOCKED'), causing CI/CD pipelines to fail immediately."
    },
    {
      icon: FileText,
      title: "How Vulnerable / Remediated Suites Work?",
      summary: "The project includes two parallel suites: terraform/vulnerable contains deliberate real-world flaws (open SSH, public RDS, plaintext secrets) for testing security gates. terraform/remediated contains enterprise-hardened equivalents (KMS keys, private subnets, least-privilege IAM)."
    },
    {
      icon: GitBranch,
      title: "How CI/CD Prevents Insecure Infrastructure?",
      summary: "In GitHub Actions (.github/workflows/security.yml), Stage 2 (terraform validate & plan) has a strict dependency on Stage 1 (Checkov security gate). If Checkov detects blocking findings, GitHub Actions cancels the deployment job, guaranteeing zero insecure resources reach cloud environments."
    }
  ];

  const faqs = [
    {
      q: "What is Infrastructure-as-Code (IaC) Security?",
      a: "IaC Security is the practice of statically scanning declarative code templates (like Terraform HCL) for misconfigurations, security vulnerabilities, and compliance violations before resources are provisioned in live cloud environments."
    },
    {
      q: "How does Checkov evaluate Terraform files without deploying them to AWS?",
      a: "Checkov parses HCL into an Abstract Syntax Tree (AST) and constructs a directed acyclic graph (DAG) of all resource blocks and their relationships. It can inspect attributes (e.g. bucket ACL) and cross-resource links (e.g. security group to EC2 attachment) entirely offline."
    },
    {
      q: "Why is static analysis better than runtime cloud security (CSPM)?",
      a: "Runtime CSPM detects vulnerabilities after infrastructure is live in AWS, meaning an attacker may already be exploiting it. Static analysis shifts security leftward into the pull request, fixing issues in seconds for zero incident-response cost."
    },
    {
      q: "How does the CI/CD Security Gate work in GitHub Actions?",
      a: "The pipeline has two sequential jobs: 'security-gate' and 'terraform-validate-and-plan'. The second job specifies 'needs: [security-gate]'. If Checkov flags any HIGH/CRITICAL violation, it exits with code 1, causing GitHub Actions to automatically skip and cancel the deployment job."
    },
    {
      q: "What is SARIF and why do we export it?",
      a: "SARIF (Static Analysis Results Interchange Format) is an OASIS JSON standard. Exporting SARIF allows GitHub's code scanning action to display security findings directly in the repository's GitHub Security tab with clickable line-by-line annotations."
    },
    {
      q: "What is the difference between soft-fail and hard-fail?",
      a: "--soft-fail reports security issues for auditing purposes but always exits with code 0 so the build continues. --hard-fail-on HIGH returns an exit code of 1 whenever High or Critical violations are found, deliberately failing the pipeline."
    },
    {
      q: "How are legitimate exceptions handled? Can rules be suppressed?",
      a: "Checkov supports inline suppressions using HCL comments (e.g. #checkov:skip=CKV_AWS_18: 'Access logs bucket does not need self-logging'). Suppressions require an audit comment and are logged in audit reports."
    },
    {
      q: "Can organizations write their own custom security rules in Checkov?",
      a: "Yes. Checkov supports declarative YAML policies (for attribute existence and regex rules) and procedural Python policies (for complex AST graph traversing). Both are demonstrated in our custom_policies/ directory."
    },
    {
      q: "Does running 'terraform validate' and 'terraform plan' in this project cost cloud money?",
      a: "No. We configured AWS provider bypass settings (skip_credentials_validation, skip_requesting_account_id, skip_metadata_api_check) along with mock environment variables. The validation and planning execute 100% offline at $0 cloud cost."
    },
    {
      q: "How does this project scale to enterprise production?",
      a: "In production, pre-commit hooks run Checkov locally on developer laptops, branch protection rules prevent merging PRs unless the Checkov security gate passes, and verified plans are applied through pipeline OIDC roles without long-lived static AWS keys."
    }
  ];

  const handleCopyCmd = (cmd: string) => {
    navigator.clipboard.writeText(cmd);
    setCopiedCmd(cmd);
    setTimeout(() => setCopiedCmd(null), 2000);
  };

  return (
    <div className="space-y-8 animate-fadeIn">
      {/* Header */}
      <div className="glass-panel p-6 rounded-2xl border border-cyan-500/20 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold font-mono text-slate-100 flex items-center space-x-2">
            <BookOpen className="w-6 h-6 text-cyan-400" />
            <span>COLLEGE PRESENTATION & VIVA DEFENSE GUIDE</span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Core IaC concepts, system architecture, live demonstration commands, and top 10 examination questions with model answers.
          </p>
        </div>

        <div className="px-3.5 py-1.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-xs font-mono text-cyan-300">
          Evaluator Ready • Complete Technical Dossier
        </div>
      </div>

      {/* Core Architectural Foundations (Requirement #13) */}
      <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-4">
        <div className="border-b border-slate-800/80 pb-3">
          <h2 className="text-sm font-bold uppercase tracking-wider font-mono text-slate-200 flex items-center space-x-2">
            <Layers className="w-4 h-4 text-cyan-400" />
            <span>Core IaC Security Architecture & Concepts</span>
          </h2>
          <p className="text-xs text-slate-400 font-mono">
            Essential foundational knowledge required for college cybersecurity project evaluation and viva defense.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {coreConcepts.map((item, idx) => {
            const Icon = item.icon;
            return (
              <div key={idx} className="p-4 rounded-xl bg-slate-950/80 border border-slate-800/80 hover:border-cyan-500/30 transition-all space-y-2">
                <div className="flex items-center space-x-2">
                  <div className="p-1.5 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                    <Icon className="w-4 h-4" />
                  </div>
                  <h3 className="text-xs font-bold font-mono text-slate-200">{item.title}</h3>
                </div>
                <p className="text-xs text-slate-400 leading-relaxed font-sans">{item.summary}</p>
              </div>
            );
          })}
        </div>
      </div>

      {/* 2-Minute Live Demo Commands */}
      <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-4">
        <div className="border-b border-slate-800/80 pb-3">
          <h2 className="text-sm font-bold uppercase tracking-wider font-mono text-slate-200 flex items-center space-x-2">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <span>Live Demonstration Commands</span>
          </h2>
          <p className="text-xs text-slate-400 font-mono">
            Execute these commands during your presentation to show both failure and pass scenarios in real-time.
          </p>
        </div>

        <div className="space-y-3">
          {demoCommands.map((item, idx) => (
            <div key={idx} className="p-4 rounded-xl bg-slate-950/80 border border-slate-800/80 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold text-slate-200">{item.title}</span>
                <button
                  onClick={() => handleCopyCmd(item.cmd)}
                  className="px-2.5 py-1 rounded-lg text-xs font-mono bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 flex items-center space-x-1"
                >
                  {copiedCmd === item.cmd ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedCmd === item.cmd ? 'Copied' : 'Copy'}</span>
                </button>
              </div>

              <div className="p-2.5 rounded-lg bg-[#02050c] font-mono text-xs text-cyan-300 border border-slate-800 overflow-x-auto">
                <code>{item.cmd}</code>
              </div>

              <p className="text-xs text-slate-400">{item.desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Top 10 Viva Defense Questions Accordion */}
      <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-4">
        <div className="border-b border-slate-800/80 pb-3">
          <h2 className="text-sm font-bold uppercase tracking-wider font-mono text-slate-200 flex items-center space-x-2">
            <HelpCircle className="w-4 h-4 text-cyan-400" />
            <span>Top 10 College Viva / Technical Defense Questions</span>
          </h2>
          <p className="text-xs text-slate-400 font-mono">
            Click any question to view the exact model technical answer recommended for your project defense.
          </p>
        </div>

        <div className="space-y-2">
          {faqs.map((faq, idx) => {
            const isOpen = openFaq === idx;
            return (
              <div 
                key={idx} 
                className="rounded-xl border border-slate-800/80 bg-slate-950/60 overflow-hidden transition-all"
              >
                <button
                  onClick={() => setOpenFaq(isOpen ? null : idx)}
                  className="w-full px-5 py-3.5 text-left flex items-center justify-between font-mono text-xs font-semibold text-slate-200 hover:text-cyan-300"
                >
                  <span>Q{idx + 1}: {faq.q}</span>
                  {isOpen ? <ChevronUp className="w-4 h-4 text-cyan-400" /> : <ChevronDown className="w-4 h-4 text-slate-500" />}
                </button>

                {isOpen && (
                  <div className="px-5 pb-4 text-xs font-sans text-slate-300 border-t border-slate-800/60 pt-3 leading-relaxed bg-[#03060e]/50">
                    <p className="text-emerald-400 font-mono font-bold mb-1">Defense Answer:</p>
                    {faq.a}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
