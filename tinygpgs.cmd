@set c=%~dpn0.cmd
@for %%f in ("%~n0.cmd") do if not exist "%~dpn0.cmd" set c=%%~dpn$PATH:f.cmd
@if "%c%"==".cmd" echo fatal: program not found: %~n0.cmd 1>&2 & exit /b 1
@for %%f in ("%c%") do set c=%%~dpnf.single
@if not exist "%c%" echo fatal: program not found: %c% 1>&2 & exit /b 1
@for %%f in ("%c%") do set p=%%~dpftinygpgs_python.exe
@if not exist "%p%" set p=python
@"%p%" "%c%" %*
