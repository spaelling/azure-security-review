# Azure Security Review

An attempt to create a Jupyter Notebook (using Polyglot) to codify the [Azure Security Review Checklist](https://github.com/Azure/review-checklists) and other general security recommendations.

The goal is to include all the checklist items to the extend that it is possibly to gain insights using code.

The notebook approach allows for use of many different languages and frameworks. We can use Microsoft Graph to gain insights into Entra ID (Azure AD), and we can use Azure Resource Graph combined with Azure Powershell or Az cli. But C#, Python, Javascript, etc. is also viable options.

An example could be to use Resource Graph combined with Azure Powershell to to review Owner access, and then look at signin-logs for the Owner users.

Combined with Markdown allows for verbosity to a level that an Excel sheet cannot do, and insights gained literally with the click of a button.

## Prerequisites

- VSCode
- Python Extension
- Polyglot Extension
- Anaconda 3

```powershell
# Install Anaconda 3 using ex. Chocolatey

# from an elevated command prompt
choco install anaconda3
# go drink a coffee - this takes a while
```