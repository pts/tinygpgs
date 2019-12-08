import sys, traceback
if sys.version_info[:2] < (2, 4):
  sys.exit('fatal: Python version >=2.4 needed for: %s' % sys.argv[0])
if sys.argv[0].endswith('/__main__.py'):
  def reverse_on_path(prog):
    """Removes directory name for prog if on $PATH."""
    import os
    import os.path
    if os.sep in prog:
      path = os.getenv('PATH', '')
      if path:
        basename = os.path.basename(prog)
        for pathdir in path.split(os.pathsep):
          pathname = os.path.join(pathdir, basename)
          if os.path.exists(pathname):
            if pathname == prog:
              return basename
            else:
              return pathname
    return prog
  sys.argv[0] = '%s -m tinygpgs' % reverse_on_path(sys.executable)
try:
  from tinygpgs import main
  sys.exit(main.main(sys.argv))
except SystemExit:
  raise
except:
  # Omit higher stack traces.
  traceback.print_exc()
  sys.exit(1)
