---
name: create-python-script
description: Create a Python script. Use this skill to create a Python script that performs a specific task or set of tasks. Provide details about the desired functionality, and the skill will generate the appropriate Python code.
---

To create a Python script using the `create-python-script` skill, you can follow these steps:
1. **Define the Task**: Clearly describe the task or set of tasks you want the Python script to perform. Be as specific as possible about the functionality you need.
2. **Provide Details**: Include any necessary details such as input parameters, expected output, and any specific conditions or requirements for the script.
3. **Generate the Script**: Use the `create-python-script` skill to generate the Python code based on the information you provided. The skill will create a script that meets your specifications.
Here’s an example of how you might use the skill:
```markdown---        
name: create-python-script
description: Create a Python script to automate data analysis. The script should read a CSV file, perform basic data cleaning, and generate summary statistics for the dataset.
---
``` 
# Python Script conventions and best practices
- All Python scripts should follow the `snake_case` naming convention (e.g., `data_analysis.py`, `file_backup.py`).
- Use docstrings to document functions and classes, including a description of their purpose, parameters, and return values.
- Follow the PEP 8 style guide for Python code to ensure readability and consistency. This includes using 4 spaces for indentation, limiting lines to 79 characters, and using blank lines to separate functions and classes.
- Use meaningful variable names that clearly indicate their purpose and content.    
- Include error handling to manage exceptions and ensure the script can handle unexpected situations gracefully.
- Always test your Python scripts to ensure they work as expected and handle edge cases appropriately.  
- Consider using virtual environments to manage dependencies and ensure that your Python scripts can run in isolated environments without conflicts.


