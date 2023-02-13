<!DOCTYPE html>
<html>
	<head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
		<title>{{.Namespace}}</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-GLhlTQ8iRABdZLl6O3oVMWSktQOp6b7In1Zl3/Jr59b6EGGoI1aFkw7cmDA6j6gD" crossorigin="anonymous">
        <style>
            td.severity-CRITICAL, tr.severity-CRITICAL td, .severity-CRITICAL a:link, .severity-CRITICAL a:visited { background-color: #c33; color: white }
            td.severity-HIGH, tr.severity-HIGH td, .severity-HIGH a:link, .severity-HIGH a:visited { background-color: orange; color: white }
            td.severity-MEDIUM, tr.severity-MEDIUM td, .severity-MEDIUM a:link, .severity-MEDIUM a:visited { background-color: #fd5 }
            table.sortable th:not(.sorttable_sorted):not(.sorttable_sorted_reverse):not(.sorttable_nosort):after { content: " \25B4\25BE" }
        </style>
    </head>
	<body>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js" integrity="sha384-w76AqPfDkMBDXo30jS1Sgez6pr3x5MlQ1ZAGC+nuZB+EYdgRZgiwxhTBTkF7CXvN" crossorigin="anonymous"></script>
        <script src="https://www.kryogenix.org/code/browser/sorttable/sorttable.js"></script>
        <nav><a href="/">namespaces</a>/{{ .Namespace }}</nav>
        <h1>Reports for {{ .Namespace }}</h1>
        <table class="table table-bordered sortable">
        <tr>
            <th>Image</th>
            <th>Critical</ht><th>High</ht><th>Medium</ht><th>Low</th><th>Unknown</ht><th>None</th>
        </tr>
	{{range .Items}}
		<tr>
            <td><a href="/{{ .Namespace }}/{{ .Name }}">{{ .Image }}</a></td>
            <td class="severity-CRITICAL">{{.Critical}}</td>
            <td class="severity-HIGH">{{.High}}</td>
            <td class="severity-MEDIUM">{{.Medium}}</td>
            <td>{{.Low}}</td>
            <td>{{.Unknown}}</td>
            <td>{{.None}}</td>
        </tr>
	{{else}}
		<tr><td colspan="6">None</td></tr>
	{{end}}
    </table>
	</body>
</html>