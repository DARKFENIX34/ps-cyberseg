function Obtener-UsuariosInactivos { 

<# 

.SYNOPSIS 

Obtiene usuarios locales habilitados que nunca han iniciado sesión. 

 

.DESCRIPTION 

Esta función busca cuentas locales habilitadas que no tienen fecha de último inicio de sesión. 

 

.EXAMPLE 

Obtener-UsuariosInactivos 

 

.NOTES 

Puede ayudar a detectar cuentas innecesarias o riesgosas en auditorías básicas. 

#> 

    Get-LocalUser | Where-Object { $_.Enabled -eq $true -and -not $_.LastLogon } 

} 

 

function Obtener-ServiciosExternos { 

<# 

.SYNOPSIS 

Obtiene servicios en ejecución que no pertenecen explícitamente a Windows. 

 

.DESCRIPTION 

Filtra servicios activos cuyo nombre descriptivo no contiene el término "Windows". 

 

.EXAMPLE 

Obtener-ServiciosExternos 

 

.NOTES 

Útil para detectar software de terceros corriendo en segundo plano. 

#> 

    Get-Service | Where-Object { $_.Status -eq "Running" -and $_.DisplayName -notmatch "Windows" } 

} 

