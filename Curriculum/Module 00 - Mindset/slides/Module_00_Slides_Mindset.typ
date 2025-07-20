#import "../../../athena-typst-theme/athena-polylux.typ": *
#import "@preview/pinit:0.1.4": *
#show: athena-theme.with(
  footer: [Marcel Schnideritsch],
  progress-bar: true,
)

#set text(font: "Noto Sans Mono", weight: "regular", size: 20pt)
#show math.equation: set text(font: "TeX Gyre Math")
#set strong(delta: 100)
#set par(justify: true)

#title-slide(
  title: [Module 00: Mindset],
  subtitle: [Introduction to the Offensive Security Mindset],
)

#slide(title: "What is the Offensive Security Mindset")[
- The offensive security mindset is characterized by a proactive approach to cybersecurity.


- It involves actively seeking vulnerabilities and weaknesses in systems to improve their security.


- This mindset is crucial for penetration testing and other offensive security practices.

]

#set page(background: image("figures/red_vs_blue_team.jpg", width: 100%, height: 100%))
#slide(title: "")[
]
#set page(background: none)

#slide(title:"")[
  #side-by-side[
    #image("figures/asimov.png")
  ][
    #text[
      "The most exciting phrase to hear in science, the one that heralds new discoveries, is not 'Eureka!' but 'That's funny...'" - Isaac Asimov
    ]
  ]
]

#slide(title: "Three Key Traits")[
- Curiosity | Stay updated on evolving threats, understand complex systems, discover hidden vulnerabilities, drive innovation, and build collaborative communities. 


- Creativity | Think like attackers, discover new attack vectors, develop custom exploits, adapt to evolving threats, and overcome obstacles. 


- Consistency | Handle complex challenges, learn from failure, adapt to changing environments, maintain motivation, and achieve long-term success. 

]

#set page(background: image("figures/zen.jpg", width: 100%, height: 100%))
#slide(title: "")[
]
#set page(background: none)

#title-slide(
  title: [Module 00: Mindset],
  subtitle: [Introduction to the Offensive Security Mindset],
)