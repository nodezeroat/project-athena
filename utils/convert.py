import re
import sys

# Converts a markdown file to a typst file (polylux)

if len(sys.argv) != 2:
    print("Usage: python convert.py <filename>")
    sys.exit(1)

filename = sys.argv[1]
f = open(filename, "r")

fout = open("slides.typ", "w")

title = ""
skip = False
buffer = []

for line in f:

    # Double stars have no effect in typst
    line = line.replace("**", "*")

    # New slide
    if "---" in line:
        if title != "":
            # convert " to \"
            title = title.replace('"', "'")
            # remove matching chars at the start and end of the string
            title = re.sub(r"^[^a-zA-Z0-9]*|[^a-zA-Z0-9]*$", "", title)

            fout.write(f'#slide(title: "{title}")[\n')

        title = ""
        skip = False

        if len(buffer) > 0:
            fout.write("\n\n".join(buffer))
            fout.write("\n]\n\n")
            buffer = []
        continue
    elif "marp: true" in line:
        skip = True
        continue
    if skip:
        continue

    if len(line.strip()) == 0:
        continue

    # Subtitles should always take precedence
    if "##" == line.strip()[0:2]:
        print(f"{line.strip()[2:]} ignoring {title}")
        title = line.strip()[2:]

    elif "#" == line.strip()[0] and title == "":
        title = line.strip()[1:]
        print(f"{title}")
    else:
        # parse images such as ![bg right 80%](./figures/intro.png) into #image("./figures/intro.png")
        if "![" in line:
            line = re.sub(r"!\[.*\]\((.*)\)", r'#image("\1")', line)
            buffer.append("// TODO fix image manually")
        # No strip for no indentation
        buffer.append(line)
