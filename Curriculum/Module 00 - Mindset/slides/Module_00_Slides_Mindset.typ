#import "../../../athena-typst-theme/athena-polylux.typ": *
#import "@preview/pinit:0.1.4": *
#show: athena-theme.with(
  footer: [Marcel Schnideritsch],
  progress-bar: true,
)

#set text(font: "Noto Sans Mono", weight: "regular", size: 20pt)
#show math.equation: set text(font: "Fira Math")
#set strong(delta: 100)
#set par(justify: true)

#title-slide(
  title: [Module 00: Mindset],
  subtitle: [Introduction to the Offensive Security Mindset],
)

#slide(title: "Outline")[
  #metropolis-outline
]

#new-section-slide("Introduction")

#slide(title: "What is the Offensive Security Mindset")[
  - The offensive security mindset is characterized by a proactive approach to cybersecurity.


  - It involves actively seeking vulnerabilities and weaknesses in systems to improve their security.


  - This mindset is crucial for penetration testing and other offensive security practices.

]

#new-section-slide("Red vs. Blue")

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


#new-section-slide("Three Key Traits")

#slide(title: "")[
  #side-by-side(gutter: 3mm, columns: (1fr, 2fr))[
    #place(
      dx: -40pt,
      dy: -80pt,
      image("figures/asimov.png", width: 130%),
    )
  ][
    #text[
      "The most exciting phrase to hear in science, the one that heralds new discoveries, is not 'Eureka!' but 'That's funny...'"

      \- Isaac Asimov
    ]
  ]
]

#slide(title: "")[
  #defbox(
    title: [Curiosity],
    [
      Stay updated on evolving threats, understand complex systems, discover hidden vulnerabilities, drive innovation, and build collaborative communities.
    ],
  )

]

#slide(title: "")[
  #defbox(
    title: [Creativity],
    [
      Think like attackers, discover new attack vectors, develop custom exploits, adapt to evolving threats, and overcome obstacles.
    ],
  )
]

#slide(title: "")[
  #defbox(
    title: [Consistency],
    [
      Handle complex challenges, learn from failure, adapt to changing environments, maintain motivation, and achieve long-term success.
    ],
  )
]

#new-section-slide("Mental Health")

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