@{
    RootModule = 'FTFLSTWD-Tools.psm1'
    ModuleVersion = '0.0.1'
    GUID = '0168d351-636d-4b78-bcb7-87adb95ac751'
    Author = 'ftflstwd'
    CompanyName = 'faithfulsteward.tech'
    Copyright = '(c) ftflstwd. All rights reserved.'
    Description = 'A PowerShell module containing tools I find useful.'
    PowerShellVersion = '7.5.1'
    FunctionsToExport = @('Get-PublicIP')
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('IPInfo', 'Network', 'PublicIP', 'PowerShell')
            LicenseUri = 'https://github.com/ftflstwd/FTFLSTWD-Tools/LICENSE' 
            ProjectUri = 'https://github.com/ftflstwd/FTFLSTWD-Tools' 
            ReleaseNotes = 'Initial release of FTFLSTWD-Tools with Get-PublicIP function.'
        }
    }
}
