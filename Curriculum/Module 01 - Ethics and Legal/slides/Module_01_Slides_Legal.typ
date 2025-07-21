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
  title: [Module 01: Legal],
  subtitle: [Legal Frameworks in Cybersecurity],
)