@{
    RootModule         = 'SeguridadEventos.psm1'
    ModuleVersion      = '1.0.0'
    GUID               = 'b1234567-89ab-cdef-0123-456789abcdef'
    Author             = 'Edgar Ramirez Tamayo y Rene Villareal Torres'
    Description        = 'Módulo para extraccion de eventos, analisis de red y reputación de IPs'
    FunctionsToExport  = @('ExtraccionDeEventos', 'MostrarConexionesYProcesos', 'InvestigacionDeDireccionesIP')
    PowerShellVersion  = '5.1'
}