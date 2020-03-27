\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{ElisaPaper}[Unified Class for ELISA white papers]
\DeclareOption*{\PassOptionsToClass{\CurrentOption}{article}}
\ProcessOptions\relax
\LoadClass[a4paper]{article}
%Packages
\RequirePackage{verbatim}
\RequirePackage{hyperref}
\RequirePackage{xargs} 
\RequirePackage[colorinlistoftodos,prependcaption,textsize=tiny]{todonotes}
\RequirePackage{booktabs}

%commands

%Layout and settings
\setlength{\parindent}{0pt}