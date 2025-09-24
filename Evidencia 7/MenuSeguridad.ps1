function MostrarMenu {
    Clear-Host
    Write-Host ""
    Write-Host "=======================================" -ForegroundColor Cyan
    Write-Host "             MENU DE SEGURIDAD         " -ForegroundColor Yellow
    Write-Host "=======================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host " [1] " -ForegroundColor Green -NoNewline; Write-Host " Extraer eventos del sistema" -ForegroundColor White
    Write-Host " [2] " -ForegroundColor Green -NoNewline; Write-Host " Mostrar conexiones y procesos" -ForegroundColor White
    Write-Host " [3] " -ForegroundColor Green -NoNewline; Write-Host " Investigar direcciones IP" -ForegroundColor White
    Write-Host " [4] " -ForegroundColor Green -NoNewline; Write-Host " Ejecutar todo automaticamente" -ForegroundColor White
    Write-Host " [0] " -ForegroundColor Red   -NoNewline; Write-Host " Salir" -ForegroundColor White
    Write-Host ""
    Write-Host "=======================================" -ForegroundColor Cyan
}

do {
    MostrarMenu
    $Opcion = Read-Host "Seleccione una opcion"

    switch ($Opcion) {
        '1' {
            ExtraccionDeEventos
        }
        '2' {
            MostrarConexionesYProcesos
        }
        '3' {
            $IPs = Read-Host "Ingrese las IPs separadas por coma (o deje vacio para usar IPs activas)"
            InvestigacionDeDireccionesIP -EntradaDeIPs $IPs
        }
        '4' {
	    ExtraccionDeEventos

	    MostrarConexionesYProcesos

	    Write-Host "`nEsperando 5 segundos antes de verificar IPs..."
	    Start-Sleep -Seconds 5

	    InvestigacionDeDireccionesIP
	}

        '0' {
            Write-Host "Saliendo del menu..."
        }
        default {
            Write-Host "Opcion invalida. Intente de nuevo."
        }
    }
} while ($Opcion -ne '0')
