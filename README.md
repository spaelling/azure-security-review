# Azure Security Review

An attempt to create a Jupyter Notebook (using Polyglot) to codify the [Azure Security Review Checklist](https://github.com/Azure/review-checklists) and other general security recommendations, like [Microsoft Security Benchmarks](https://learn.microsoft.com/en-us/security/benchmark/azure/overview).

The goal is to include all the checklist items and controls to the extend that it is possibly to gain insights using code.

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

Note that this also works in MacOS.

## Development

Figuring out how to gather the necessary data for a control or recommendation can sometimes be difficult. For Microsoft Graph I work with [Microsoft Graph REST API v1.0 endpoint reference](https://learn.microsoft.com/en-us/graph/api/overview?view=graph-rest-1.0) (and sometimes the beta API).

It can sometimes help to use ex. the Azure portal and have the developer tools open. Filter for ex. `graph` to get an idea of how the portal works with the Graph API.

Use [Graph Explorer](https://developer.microsoft.com/en-us/graph/graph-explorer) to test. Both the explorer and endpoint reference documentation has code snippets.

It is not always clear what permissions are required. Most of the time it is clearly stated. If possible work with only `read` permissions.