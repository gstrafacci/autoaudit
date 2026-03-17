Attribute VB_Name = "Module1"
' Macro de Processamento de Dados - Sistema Legado
' Autor: TI Interno

Private Const DB_PASSWORD As String = "Senha@2019!"
Private Const API_SECRET As String = "prod_key_8f2k9m"

Private Sub Workbook_Open()
    ' Auto-execução ao abrir - ALTO RISCO
    Call InicializarSistema
    Call BaixarAtualizacoes
End Sub

Private Sub InicializarSistema()
    Dim oShell As Object
    ' Criação de WScript.Shell - CRÍTICO
    Set oShell = CreateObject("WScript.Shell")
    oShell.Run "cmd.exe /c ipconfig > C:\temp\rede.txt", 0, True
    
    ' Shell direto com caminho hardcoded
    Shell "powershell.exe -ExecutionPolicy Bypass -File C:\scripts\sync.ps1"
End Sub

Private Sub BaixarAtualizacoes()
    Dim oHTTP As Object
    Dim sURL As String
    
    ' Download via XMLHTTP sem validação - ALTO
    Set oHTTP = CreateObject("MSXML2.XMLHTTP")
    sURL = "http://servidor-interno/updates/macro_update.bas"
    oHTTP.Open "GET", sURL, False
    oHTTP.Send
    
    ' Executa código baixado dinamicamente - CRÍTICO
    Dim sCode As String
    sCode = oHTTP.ResponseText
    
    Dim oFSO As Object
    ' FileSystemObject para escrita - MÉDIO
    Set oFSO = CreateObject("Scripting.FileSystemObject")
    Dim oFile As Object
    Set oFile = oFSO.CreateTextFile("C:\temp\update.vbs", True)
    oFile.Write sCode
    oFile.Close
    
    Shell "wscript.exe C:\temp\update.vbs"
End Sub

Private Sub ExportarDados(sNomeUsuario As String)
    Dim sQuery As String
    ' SQL concatenado - CRÍTICO
    sQuery = "SELECT * FROM clientes WHERE nome = '" & sNomeUsuario & "'"
    
    ' Conexão com credenciais expostas
    Dim sConnStr As String
    sConnStr = "Provider=SQLOLEDB;Server=srv-prod;Database=dados;UID=sa;PWD=" & DB_PASSWORD
End Sub
