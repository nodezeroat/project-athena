#import "../../../typst-athena-slides-template/1.0.1/src/lib.typ": *

#show: athena-theme.with(
  font: "Berkeley Mono",
  config-info(
    title: [Module 00: Mindset],
    subtitle: [Introduction to the Offensive Security Mindset],
    authors: [*Marcel Schnideritsch*],
    extra: [],
    footer: [Marcel Schnideritsch],
  ),
  config-common(
    handout: false,
  ),
)

#title-slide()

#section-slide(title: "Introduction")

#slide(title: "What is the Offensive Security Mindset")[
  - The offensive security mindset is characterized by a proactive approach to cybersecurity.


  - It involves actively seeking vulnerabilities and weaknesses in systems to improve their security.


  - This mindset is crucial for penetration testing and other offensive security practices.

]

#section-slide(title: "Red vs. Blue")

#set page(background: image("figures/red_vs_blue_team.jpg", width: 100%, height: 100%))
#slide(title: "")[
]
#set page(background: none)

#slide(title: "Red Team")[
  - Offensive security experts
  - Simulate real-world attacks
  - Identify and exploit vulnerabilities
  - Goal: Test defenses and uncover weaknesses
]

#slide(title: "Blue Team")[
  - Defensive security experts
  - Protect systems from attacks
  - Monitor, detect, and respond to threats
  - Goal: Strengthen defenses and mitigate risks
]

#slide(title: "Purple Team")[
  - Collaboration between Red and Blue Teams
  - Share knowledge and techniques
  - Ensures that attack insights (Red) improve defenses (Blue)
  - Goal: Continuous improvement of security through teamwork
]


#section-slide(title: "Three Key Traits")

#slide(title: "")[
  #grid(
    columns: (1fr, 2fr),
    gutter: 3mm,
    align: (center, center),
  )[
    #place(
      dx: -41pt,
      dy: -88pt,
      image("figures/asimov.png", width: 140%),
    )
  ][
    // Right: quote
    #text(size: 24pt)[
      “The most exciting phrase to hear in science, the one that heralds new discoveries,
      is not ‘Eureka!’ but ‘That’s funny…’”
    ]

    #text(size: 14pt, style: "italic")[— Isaac Asimov]
  ]
]

#slide(title: "")[
  #color-block(
    title: [Curiosity],
    [
      Stay updated on evolving threats, understand complex systems, discover hidden vulnerabilities, drive innovation, and build collaborative communities.
    ],
  )

]

#slide(title: "")[
  #color-block(
    title: [Creativity],
    [
      Think like attackers, discover new attack vectors, develop custom exploits, adapt to evolving threats, and overcome obstacles.
    ],
  )
]

#slide(title: "")[
  #color-block(
    title: [Consistency],
    [
      Handle complex challenges, learn from failure, adapt to changing environments, maintain motivation, and achieve long-term success.
    ],
  )
]

#section-slide(title: "Mental Health")

#slide(title: "Burnout")[
  #image("./figures/burnout_01.png", width: 100%)
]

#slide(title: "Burnout")[
  #image("./figures/burnout_02.png", width: 100%)
]

#slide(title: "Burnout")[
  #image("./figures/burnout_03.png", width: 100%)
]

#slide(title: "Burnout")[
  #image("./figures/burnout_04.png", width: 100%)
]

#slide(title: "Prevent Burnout")[
  - Work-Life Balance: Set boundaries and recharge.
  - Collaborate: Don’t hack alone — support and be supported.
  - Keep Learning: Curiosity keeps burnout at bay.
  - Manage Stress: Use healthy coping strategies.
  - Celebrate Wins: Big or small, every success counts.
  - Seek Feedback: Growth comes from reflection.
  - Learn from Failure: Every setback teaches you something new.
]

#set page(background: image("figures/zen.jpg", width: 100%, height: 100%))
#slide(title: "")[
]
#set page(background: none)

#title-slide(
  title: [Module 00: Mindset],
  subtitle: [Introduction to the Offensive Security Mindset],
)
