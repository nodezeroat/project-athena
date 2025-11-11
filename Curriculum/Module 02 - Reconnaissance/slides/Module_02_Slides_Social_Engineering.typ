#import "../../../typst-athena-slides-template/1.0.1/src/lib.typ": *

#show: athena-theme.with(
  font: "Berkeley Mono",
  config-info(
    title: [Module 02: Reconnaissance],
    subtitle: [Social Engineering in Reconnaissance],
    authors: [*Project Athena*],
    extra: [],
    footer: [Module 02 - Social Engineering],
  ),
  config-common(
    handout: false,
  ),
)

#title-slide()

#slide(title: "Social Engineering in Reconnaissance")[
  *Definition:* Exploiting human psychology to gather information not available through technical means.

  *Focus:* This lecture covers social engineering for *information gathering*, not direct system compromise.

  #color-block(
    title: [Note:],
    [
      For comprehensive social engineering coverage, see Module 22 - Social Engineering
    ]
  )
]

#slide(title: "Why Social Engineering?")[
  *The Human Element:*

  - Perfect firewalls, encrypted communications, strong access controls
  - BUT: One employee sharing information can unravel all defenses
  - *People are often the weakest link in security*

  *Social Engineering Exploits:*
  - Trust and authority
  - Desire to be helpful
  - Fear of consequences
  - Lack of security awareness
  - Time pressure and stress
  - Cognitive biases
]

#section-slide(title: "Pretext Development")

#slide(title: "What is Pretexting?")[
  *Creating a fabricated scenario to engage target and extract information*

  *Common Pretexts for Reconnaissance:*

  1. *IT Support* - "Updating our records, verify your username?"
  2. *Vendor/Supplier* - "Confirming delivery address"
  3. *Survey/Research* - "Technology survey for your industry"
  4. *New Employee* - "Learning our tech stack, what do you use?"
  5. *Potential Customer* - "Tell me about your infrastructure"
]

#slide(title: "Building a Credible Pretext")[
  *Requirements:*

  - Research target organization thoroughly first
  - Use correct terminology and jargon
  - Reference real people, departments, events
  - Match communication style to role
  - Have answers ready for verification questions
  - Create supporting artifacts (email, phone)

  *Example:* Calling as "IT support" but not knowing the company's actual IT department name = instant red flag
]

#slide(title: "Information Targets")[
  *What to Gather:*

  *Organizational:*
  - Structure, departments, employees
  - Email formats, internal terminology

  *Technical:*
  - Operating systems, software versions
  - Security products (antivirus, firewalls)
  - Authentication methods (SSO, MFA)
  - Cloud services, network architecture

  *Security:*
  - Badge systems, visitor policies
  - Password policies, physical security

  *Operational:*
  - Working hours, key personnel schedules
  - Third-party vendors
]

#section-slide(title: "Techniques")

#slide(title: "1. Phone-based (Vishing)")[
  *Voice Phishing - Information Gathering*

  *Advantages:*
  - Real-time interaction allows adaptation
  - Voice conveys authority and urgency
  - Less permanent record than email
  - Can build rapport quickly

  *Techniques:*
  - Call during busy hours (people rushed)
  - Use official-sounding language
  - Appropriate background noise
  - Caller ID spoofing
  - "Foot in the door" (start small)
]

#slide(title: "Vishing Example: Help Desk")[
  ```
  Attacker: "Hi, this is John from corporate IT.
            We're auditing our systems. What OS
            is on your workstation?"

  Target: "Windows 10."

  Attacker: "Great, and are you using the standard
            antivirus or did your department get
            an exception?"

  Target: "We have Symantec Endpoint Protection."

  Attacker: "Perfect. What's your employee ID format?
            Is it first initial, last name?"

  Target: "Actually it's first name dot last name."
  ```

  *Information Gained:* OS, antivirus, email format, potential username format
]

#slide(title: "2. Email-based Reconnaissance")[
  *Unlike credential phishing, seeks information responses*

  *Technology Survey Example:*
  ```
  Subject: Quick Technology Survey - 5 Minutes

  We're researching enterprise technology adoption
  in the [Industry] sector.

  1. What operating systems does your organization use?
  2. Do you use cloud services? Which providers?
  3. What security certifications do you maintain?
  4. How many employees in your IT department?
  ```

  *Benefits:* Multiple targets, higher response rate, builds legitimacy
]

#slide(title: "3. In-person Social Engineering")[
  *Tailgating / Piggybacking:*
  - Follow authorized personnel through secure entrances
  - Observe badge systems, floor layouts
  - Security camera positions
  - Employee behaviors and security culture

  *Pretexting On-Site:*
  - *Delivery Person* - Package gives reason to wander
  - *Contractor* - Clipboard + high-vis vest = invisible
  - *Job Interview* - Legitimate reason, can ask questions
  - *Building Inspector* - Authority figure people don't question
]

#slide(title: "In-person Observation Points")[
  *What to Look For:*

  - Badge details (format, color coding)
  - Desk labels and org charts
  - Whiteboards (projects, IPs, passwords!)
  - Sticky notes on monitors
  - Overheard conversations
  - Dumpster diving opportunities (unlocked dumpsters)

  *Physical Reconnaissance:*
  - Building layout and entry points
  - Security guard procedures
  - Visitor sign-in process
]

#slide(title: "4. Social Media Intelligence")[
  *Direct Engagement:*
  - Connect on LinkedIn with fake profiles
  - Join professional groups
  - Engage in discussions to build rapport
  - Ask technical questions revealing infrastructure

  *Indirect Gathering:*
  - Analyze employee posts for:
    - Photos from offices (whiteboards, screens, badges)
    - Complaints about work systems
    - Mentions of technologies
    - Travel patterns and schedules
    - Personal info for security questions
]

#slide(title: "LinkedIn Intelligence Example")[
  ```
  Profile: "Senior Network Engineer at TargetCorp"

  Recent Post: "Finally got our new Palo Alto
               firewalls configured! Three weeks
               of late nights but network is
               faster now."

  Intelligence Gained:
  - Use Palo Alto Networks firewalls
  - Recently implemented (potential misconfigs)
  - Network engineer works late hours
  - Expressed frustration (vulnerable to helpfulness)
  ```
]

#section-slide(title: "Psychological Principles")

#slide(title: "Cialdini's Principles of Influence")[
  1. *Authority* - People obey authority figures
     - Claim to be from senior management, IT, security

  2. *Reciprocity* - People feel obligated to return favors
     - "I helped you last time, can you help me now?"

  3. *Social Proof* - People follow what others do
     - "Everyone in your department already provided this"

  4. *Scarcity* - Urgency creates pressure
     - "We need this by end of day"

  5. *Liking* - People say yes to those they like
     - Find common ground, compliment appropriately

  6. *Commitment/Consistency* - Act consistently with prior commitments
     - Get small agreement first, build to larger requests
]

#slide(title: "Cognitive Biases and Triggers")[
  *Cognitive Biases:*
  - *Authority Bias* - Trusting authority without verification
  - *Confirmation Bias* - Hearing what they expect
  - *Availability Heuristic* - Recent events seem more likely

  *Emotional Triggers:*
  - *Fear* - "Your account has been compromised"
  - *Greed* - "You've won a prize"
  - *Curiosity* - "Check out this interesting link"
  - *Helpfulness* - "I really need your help"

  *All designed to bypass rational thinking*
]

#section-slide(title: "Practical Examples")

#slide(title: "Example 1: Technical Information")[
  *Scenario:* Want to know antivirus solution

  *Approach:* Call as potential customer

  ```
  Attacker: "I'm evaluating managed security
            services. Before we proceed, what
            endpoint protection do you use for
            compatibility?"

  Receptionist: "Let me transfer you to IT."

  IT: "We're using CrowdStrike Falcon."

  Attacker: "Perfect, and Windows primarily or mixed?"

  IT: "Mostly Windows 10, some Macs in creative."
  ```

  *Result:* Antivirus, OS distribution, org structure
]

#slide(title: "Example 2: Organizational Intelligence")[
  *Scenario:* Want employee directory for phishing

  *Approach:* LinkedIn fake recruiter

  ```
  Message: "Hi [Name], I have an exciting opportunity.
           Who's the best person to talk to about
           enterprise software licensing? Could you
           refer colleagues interested in careers?"

  Target: "Talk to John Smith, Director of Procurement.
          I'll send this to a few interested people."
  ```

  *Result:* Key decision-maker identified, employee referrals, potential insider recruitment
]

#slide(title: "Example 3: Physical Security")[
  *Scenario:* Need badge system info for physical pentest

  *Approach:* Fake security vendor assessment

  ```
  Attacker: "This is Sarah from SecureTech conducting
            mandatory security assessment. What badge
            system are you using?"

  Security: "HID proximity cards."

  Attacker: "Do you have mantrap at main entrance
            or just badge readers?"

  Security: "Badge readers, but data center has mantrap."

  Attacker: "When does security guard shift change?"

  Security: "7 AM and 7 PM."
  ```

  *Result:* Badge type (can clone), data center location, optimal entry times
]

#section-slide(title: "Defense Strategies")

#slide(title: "Organizational Defenses")[
  *1. Security Awareness Training*
  - Regular training on social engineering tactics
  - Simulated phishing/vishing exercises
  - "Trust but verify" culture

  *2. Verification Procedures*
  - Callback verification for sensitive requests
  - Never provide info based on inbound calls alone
  - Out-of-band communication channels

  *3. Information Classification*
  - Mark sensitive information clearly
  - Establish what can be shared publicly
  - Escalation procedures for unclear situations
]

#slide(title: "Individual Defenses")[
  *Red Flags:*
  - Urgent requests for information/action
  - Requests to bypass normal procedures
  - Callers who verify legitimacy by asking YOU
  - Emotional manipulation
  - Requests to keep interaction secret
  - Generic greetings

  *Best Practices:*
  1. *Verify Identity* - Callback independently
  2. *Question Authority* - Claims ≠ reality
  3. *Take Your Time* - Resist pressure tactics
  4. *Follow Policy* - Procedures exist for reason
  5. *When in Doubt, Escalate*
  6. *Document* - Keep records
  7. *Report* - Tell security about attempts
]

#slide(title: "Physical Security Defenses")[
  *Policies:*
  - Challenge unknown persons
  - Always wear and display badges
  - Don't hold doors for others (even if seems rude)
  - Report tailgating to security
  - Escort visitors at all times
  - Clean desk policy (no sensitive info visible)

  *Culture:*
  - Make security everyone's responsibility
  - Reward reporting suspicious behavior
  - Regular reminders and training
]

#section-slide(title: "Legal and Ethical")

#slide(title: "Authorization is Critical")[
  #color-block(
    title: [Absolute Requirement:],
    [
      *Social engineering for reconnaissance requires explicit written authorization*
    ]
  )

  *Rules of Engagement must specify:*
  - Whether social engineering is permitted
  - Some clients prohibit it entirely
  - Scope: who can be targeted
  - Document all attempts meticulously
]

#slide(title: "Legal Risks")[
  *Potential Violations:*
  - Impersonation of officials (law enforcement, government) - may be illegal
  - Misrepresentation can violate laws
  - Recording conversations requires consent (jurisdiction-dependent)
  - Trespassing for unauthorized physical access
  - Wire fraud for telephone-based pretexting

  *Scope Limitations:*
  - Only target specified individuals/organizations
  - Stop if someone becomes distressed
  - Never create lasting harm
  - Respect boundaries in RoE
]

#slide(title: "Responsible Disclosure")[
  *After authorized social engineering tests:*

  - Debrief participants sensitively
  - Explain how they were targeted
  - Use as teaching moments, NOT punishment
  - Provide constructive feedback
  - Focus on organizational improvements
  - Document lessons learned
  - Update training based on results

  *Goal:* Improve security posture, not shame individuals
]

#section-slide(title: "Integration with Technical Recon")

#slide(title: "Combining Social and Technical")[
  *Social engineering should complement, not replace, technical reconnaissance:*

  1. *Validate Technical Findings* - Confirm technical discoveries
  2. *Fill Gaps* - Gather info not available technically
  3. *Test Defenses* - Assess both technical and human controls
  4. *Prioritize Targets* - Reveals high-value technical targets
  5. *Craft Payloads* - Information helps create convincing attacks

  *Example:* Technical scan shows Windows, social engineering confirms specific antivirus and patch schedule
]

#section-slide(title: "Key Takeaways")

#slide(title: "Summary")[
  *Critical Points:*

  - Social engineering exploits human psychology, not technical vulnerabilities
  - In reconnaissance, gathers info not readily available technically
  - Multiple vectors: phone, email, in-person, social media
  - Psychological principles (authority, reciprocity) make it effective
  - Defense requires both organizational measures and individual awareness
  - Always obtain authorization before social engineering tests
  - Integrate with technical reconnaissance for comprehensive assessment
  - Human security is as important as technical security
]

#slide(title: "Remember")[
  #color-block(
    title: [Key Insight:],
    [
      *Security is ultimately about people, not just technology*
    ]
  )

  The most sophisticated technical controls can be bypassed through simple conversation if human factors aren't addressed.

  Understanding social engineering tactics—both for offensive testing and defensive awareness—is essential for comprehensive security.
]

#slide(title: "Resources")[
  *Books:*
  - "The Art of Deception" by Kevin D. Mitnick
  - "Social Engineering: The Science of Human Hacking" by Christopher Hadnagy
  - "Influence: The Psychology of Persuasion" by Robert B. Cialdini

  *Related Modules:*
  - Module 22 - Social Engineering (comprehensive)
  - Module 01 - Ethics and Legal
]

#title-slide()
