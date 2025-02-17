# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = 'digdoc command-line tool'
copyright = '2025, Fabian Krusch, Leonie Seelisch, Markus Ziehe'
author = 'Fabian Krusch, Leonie Seelisch, Markus Ziehe'
release = '1.0'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = ['breathe']

templates_path = ['_templates']
exclude_patterns = []



# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'classic'
html_static_path = ['_static']

# -- Breathe _________________________________________________________________

breathe_projects = {"digdoc command-line tool": "../xml"}
breathe_default_project = "digdoc command-line tool"
