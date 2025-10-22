#!/bin/bash
cd ../Curriculum
# Prompt the user for the name of the module
echo "Enter the name of the module:"
read MODULE_NAME

# Create the module directory
mkdir "$MODULE_NAME"
cd "$MODULE_NAME"

# Create the lectures directory and add overview.md
mkdir lectures

# Create the assignments directory
mkdir assignments

# Create the resources directory
mkdir resources
cd resources
mkdir images

# Create the README.md file for the module
cd ../
touch introduction.md
