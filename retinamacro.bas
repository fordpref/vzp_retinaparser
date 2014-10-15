Attribute VB_Name = "Module1"
Sub FormatRetina()
'
' FormatRetina Macro
'

' Setup Error handling, needed for fields that may not exist.
On Error Resume Next

' Delete Unneeded Headers/columns
    ActiveWorkbook.Worksheets("Sheet1").Activate
    Range("Table1[[#All],[netBIOSName]]").Select
    Selection.Delete Shift:=xlToLeft
    Range("Table1[[#All],[netBIOSDomain]]").Select
    Selection.Delete Shift:=xlToLeft
    Range("Table1[[#All],[dnsName]]").Select
    Selection.Delete Shift:=xlToLeft
    Range("Table1[[#All],[mac]]").Select
    Selection.Delete Shift:=xlToLeft
    Range("Table1[[#All],[cpe]]").Select
    Selection.Delete Shift:=xlToLeft
    Range("Table1[[#All],[rthID]]").Select
    Selection.Delete Shift:=xlToLeft
    Range("Table1[[#All],[cce]]").Select
    Selection.Delete Shift:=xlToLeft
    Range("Table1[[#All],[date]]").Select
    Selection.Delete Shift:=xlToLeft
    Range("Table1[[#All],[risk]]").Select
    Selection.Delete Shift:=xlToLeft


' This section focuses on Table Headers that may not be there.
' Basically it continues past any error of the header field not being there
' And otherwise deletes the column.

    Range("Table1[[#All],[pciPassFail]]").Select
    If Err.Number <> 0 Then
    Err.Number = 0
    Else
    Selection.Delete Shift:=xlToLeft
    End If
    
    Range("Table1[[#All],[pciLevel]]").Select
    If Err.Number <> 0 Then
    Err.Number = 0
    Else
    Selection.Delete Shift:=xlToLeft
    End If
    
    Range("Table1[[#All],[pciReason]]").Select
    If Err.Number <> 0 Then
    Err.Number = 0
    Else
    Selection.Delete Shift:=xlToLeft
    End If
    

    
    Range("Table1[[#All],[cvssScore]]").Select
    If Err.Number <> 0 Then
    Err.Number = 0
    Else
    Selection.Delete Shift:=xlToLeft
    End If
    
    Range("Table1[[#All],[context]]").Select
    If Err.Number <> 0 Then
    Err.Number = 0
    Else
    Selection.Delete Shift:=xlToLeft
    End If
    
    Range("Table1[[#All],[jobName]]").Select
    If Err.Number <> 0 Then
    Err.Number = 0
    Else
    Selection.Delete Shift:=xlToLeft
    End If
    
    Range("Table1[[#All],[fileName]]").Select
    If Err.Number <> 0 Then
    Err.Number = 0
    Else
    Selection.Delete Shift:=xlToLeft
    End If
    
    Range("Table1[[#All],[scannerVersion]]").Select
    If Err.Number <> 0 Then
    Err.Number = 0
    Else
    Selection.Delete Shift:=xlToLeft
    End If
    
    Range("Table1[[#All],[auditsRevision]]").Select
    If Err.Number <> 0 Then
    Err.Number = 0
    Else
    Selection.Delete Shift:=xlToLeft
    End If
    
    Range("Table1[[#All],[credentials]]").Select
    If Err.Number <> 0 Then
    Err.Number = 0
    Else
    Selection.Delete Shift:=xlToLeft
    End If
    
    Range("Table1[[#All],[auditGroups]]").Select
    If Err.Number <> 0 Then
    Err.Number = 0
    Else
    Selection.Delete Shift:=xlToLeft
    End If
    
    Range("Table1[[#All],[addressGroups]]").Select
    If Err.Number <> 0 Then
    Err.Number = 0
    Else
    Selection.Delete Shift:=xlToLeft
    End If
    
    Range("Table1[[#All],[ipRanges]]").Select
    If Err.Number <> 0 Then
    Err.Number = 0
    Else
    Selection.Delete Shift:=xlToLeft
    End If
    
    Range("Table1[[#All],[attempted]]").Select
    If Err.Number <> 0 Then
    Err.Number = 0
    Else
    Selection.Delete Shift:=xlToLeft
    End If
    
    Range("Table1[[#All],[scanned]]").Select
    If Err.Number <> 0 Then
    Err.Number = 0
    Else
    Selection.Delete Shift:=xlToLeft
    End If
    
    Range("Table1[[#All],[noAdmin]]").Select
    If Err.Number <> 0 Then
    Err.Number = 0
    Else
    Selection.Delete Shift:=xlToLeft
    End If
    
    Range("Table1[[#All],[noResponse]]").Select
    If Err.Number <> 0 Then
    Err.Number = 0
    Else
    Selection.Delete Shift:=xlToLeft
    End If
    
    Range("Table1[[#All],[duration]]").Select
    If Err.Number <> 0 Then
    Err.Number = 0
    Else
    Selection.Delete Shift:=xlToLeft
    End If
    
    
    'Change sevCode to CAT
    Range("Table1[[#Headers],[sevCode]]").Select
    ActiveCell.FormulaR1C1 = "CAT"
    
    'Move columns to correct order
    Range("Table1[[#All],[start]]").Select
    Selection.Cut
    Range("Table1[[#All],[ip]]").Select
    Selection.Insert Shift:=xlToRight
    
    Range("Table1[[#All],[CAT]]").Select
    Selection.Cut
    Range("Table1[[#All],[name]]").Select
    Selection.Insert Shift:=xlToRight
    
    Range("Table1[[#All],[exploit]]").Select
    Selection.Cut
    Range("Table1[[#All],[name]]").Select
    Selection.Insert Shift:=xlToRight
    
    'Change Column Widths
    Range("Table1[[#All],[name]]").ColumnWidth = 20
    Range("Table1[[#All],[description]]").ColumnWidth = 20
    Range("Table1[[#All],[fixInformation]]").ColumnWidth = 20
    Range("Table1[[#All],[exploit]]").ColumnWidth = 9
    Range("Table1[[#All],[IAV]]").ColumnWidth = 15
    Range("Table1[[#All],[CAT]]").ColumnWidth = 12
    Range("Table1[[#All],[start]]").ColumnWidth = 19
    

' This is the initial Sort
    ActiveWorkbook.Worksheets("Sheet1").ListObjects("Table1").Sort.SortFields.Clear
    ActiveWorkbook.Worksheets("Sheet1").ListObjects("Table1").Sort.SortFields.Add _
        Key:=Range("Table1[[#All],[CAT]]"), SortOn:=xlSortOnValues, Order:= _
        xlAscending, DataOption:=xlSortNormal
    ActiveWorkbook.Worksheets("Sheet1").ListObjects("Table1").Sort.SortFields.Add _
        Key:=Range("Table1[[#All],[iav]]"), SortOn:=xlSortOnValues, Order:= _
        xlAscending, DataOption:=xlSortNormal
    ActiveWorkbook.Worksheets("Sheet1").ListObjects("Table1").Sort.SortFields.Add _
        Key:=Range("Table1[[#All],[ip]]"), SortOn:=xlSortOnValues, Order:= _
        xlAscending, DataOption:=xlSortNormal
    ActiveWorkbook.Worksheets("Sheet1").ListObjects("Table1").Sort.SortFields.Add _
        Key:=Range("Table1[[#All],[exploit]]"), SortOn:=xlSortOnValues, Order:= _
        xlDescending, DataOption:=xlSortNormal
    With ActiveWorkbook.Worksheets("Sheet1").ListObjects("Table1").Sort
        .Header = xlYes
        .MatchCase = False
        .Orientation = xlTopToBottom
        .SortMethod = xlPinYin
        .Apply
    End With
    
' This colors the rows
    For Each Cell In Worksheets("sheet1").Range(Worksheets("sheet1").Range("F2"), Worksheets("sheet1").Range("F2").End(xlDown))
        If Cell.Value = "Category I" Then
            Cell.EntireRow.Interior.Color = RGB(255, 0, 0)
        ElseIf Cell.Value = "Category II" Then
            Cell.EntireRow.Interior.Color = RGB(255, 192, 0)
        ElseIf Cell.Value = "Category III" Then
            Cell.EntireRow.Interior.Color = RGB(255, 255, 0)
        ElseIf Cell.Value = "Category IV" Then
            Cell.EntireRow.Interior.Color = RGB(0, 255, 0)
        End If
    Next Cell
    
' Here we delete the initial extra sheet2 and sheet3, then copy sorted and colored sheet1 to the other 3 sheets
' and rename them appropriately
    ActiveSheet.Name = "By CAT"
    Application.DisplayAlerts = False
    ActiveWorkbook.Worksheets("Sheet2").Delete
    ActiveWorkbook.Worksheets("Sheet3").Delete
    Application.DisplayAlerts = True
    
    ActiveWorkbook.Worksheets("By CAT").Copy After:=Sheets(ActiveWorkbook.Sheets.Count)
    ActiveSheet.Name = "By IP"
    ActiveWorkbook.Worksheets("By IP").Copy After:=Sheets(ActiveWorkbook.Sheets.Count)
    ActiveSheet.Name = "By Exploit"
    ActiveWorkbook.Worksheets("By Exploit").Copy After:=Sheets(ActiveWorkbook.Sheets.Count)
    ActiveSheet.Name = "By IAV"
    


' Now we format each of the additional sheets starting with By IP
    ActiveWorkbook.Worksheets("By IP").Activate
    ' This loop finds whatever excel named the new table and changes to Table2
    Dim oSh As Worksheet
    Dim oLo As ListObject
    Set oSh = ActiveSheet
    For Each oLo In oSh.ListObjects
         Application.Goto oLo.Range
         oLo.Name = "Table2"
    Next
    ' Now we sort By IP and at the end we select Cell A2
    ActiveWorkbook.Worksheets("By IP").ListObjects("Table2").Sort.SortFields.Clear
    ActiveWorkbook.Worksheets("By IP").ListObjects("Table2").Sort.SortFields.Add _
        Key:=Range("Table2[[#All],[ip]]"), SortOn:=xlSortOnValues, Order:= _
        xlAscending, DataOption:=xlSortNormal
    ActiveWorkbook.Worksheets("By IP").ListObjects("Table2").Sort.SortFields.Add _
        Key:=Range("Table2[[#All],[CAT]]"), SortOn:=xlSortOnValues, Order:= _
        xlAscending, DataOption:=xlSortNormal
    ActiveWorkbook.Worksheets("By IP").ListObjects("Table2").Sort.SortFields.Add _
        Key:=Range("Table2[[#All],[iav]]"), SortOn:=xlSortOnValues, Order:= _
        xlAscending, DataOption:=xlSortNormal
    ActiveWorkbook.Worksheets("By IP").ListObjects("Table2").Sort.SortFields.Add _
        Key:=Range("Table2[[#All],[exploit]]"), SortOn:=xlSortOnValues, Order:= _
        xlDescending, DataOption:=xlSortNormal
    With ActiveWorkbook.Worksheets("By IP").ListObjects("Table2").Sort
        .Header = xlYes
        .MatchCase = False
        .Orientation = xlTopToBottom
        .SortMethod = xlPinYin
        .Apply
    End With
    Range("A2").Select
    
    
    
    ActiveWorkbook.Worksheets("By Exploit").Activate
     Set oSh = ActiveSheet
     For Each oLo In oSh.ListObjects
         Application.Goto oLo.Range
         oLo.Name = "Table3"
     Next
    ' Now we sort By Exploit and at the end we select Cell A2
    ActiveWorkbook.Worksheets("By Exploit").ListObjects("Table3").Sort.SortFields.Clear
    ActiveWorkbook.Worksheets("By Exploit").ListObjects("Table3").Sort.SortFields.Add _
        Key:=Range("Table3[[#All],[exploit]]"), SortOn:=xlSortOnValues, Order:= _
        xlDescending, DataOption:=xlSortNormal
    ActiveWorkbook.Worksheets("By Exploit").ListObjects("Table3").Sort.SortFields.Add _
        Key:=Range("Table3[[#All],[CAT]]"), SortOn:=xlSortOnValues, Order:= _
        xlAscending, DataOption:=xlSortNormal
    ActiveWorkbook.Worksheets("By Exploit").ListObjects("Table3").Sort.SortFields.Add _
        Key:=Range("Table3[[#All],[iav]]"), SortOn:=xlSortOnValues, Order:= _
        xlAscending, DataOption:=xlSortNormal
    ActiveWorkbook.Worksheets("By Exploit").ListObjects("Table3").Sort.SortFields.Add _
        Key:=Range("Table3[[#All],[ip]]"), SortOn:=xlSortOnValues, Order:= _
        xlAscending, DataOption:=xlSortNormal
    With ActiveWorkbook.Worksheets("By Exploit").ListObjects("Table3").Sort
        .Header = xlYes
        .MatchCase = False
        .Orientation = xlTopToBottom
        .SortMethod = xlPinYin
        .Apply
    End With
    Range("A2").Select
    
    
    
    ActiveWorkbook.Worksheets("By IAV").Activate
     Set oSh = ActiveSheet
     For Each oLo In oSh.ListObjects
         Application.Goto oLo.Range
         oLo.Name = "Table4"
     Next
    ' Now we sort By IAV and at the end we select Cell A2
    ActiveWorkbook.Worksheets("By IAV").ListObjects("Table4").Sort.SortFields.Clear
    ActiveWorkbook.Worksheets("By IAV").ListObjects("Table4").Sort.SortFields.Add _
        Key:=Range("Table4[[#All],[iav]]"), SortOn:=xlSortOnValues, Order:= _
        xlAscending, DataOption:=xlSortNormal
    ActiveWorkbook.Worksheets("By IAV").ListObjects("Table4").Sort.SortFields.Add _
        Key:=Range("Table4[[#All],[CAT]]"), SortOn:=xlSortOnValues, Order:= _
        xlAscending, DataOption:=xlSortNormal
    ActiveWorkbook.Worksheets("By IAV").ListObjects("Table4").Sort.SortFields.Add _
        Key:=Range("Table4[[#All],[exploit]]"), SortOn:=xlSortOnValues, Order:= _
        xlDescending, DataOption:=xlSortNormal
    ActiveWorkbook.Worksheets("By IAV").ListObjects("Table4").Sort.SortFields.Add _
        Key:=Range("Table4[[#All],[ip]]"), SortOn:=xlSortOnValues, Order:= _
        xlAscending, DataOption:=xlSortNormal
    With ActiveWorkbook.Worksheets("By IAV").ListObjects("Table4").Sort
        .Header = xlYes
        .MatchCase = False
        .Orientation = xlTopToBottom
        .SortMethod = xlPinYin
        .Apply
    End With
    Range("A2").Select
    
    Sheets("By CAT").Activate
    Range("A2").Select
End Sub


