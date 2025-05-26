.PHONY: all clean

DEPENDS=$(shell ls *.tex) cryptobib/crypto.bib 
NAME=main
all: pdflatex

pdflatex: $(NAME).tex $(DEPENDS) $(BIBS)
	xelatex $(NAME).tex $(DEPENDS)
	bibtex $(NAME)
	xelatex $(NAME).tex $(DEPENDS)
	xelatex $(NAME).tex $(DEPENDS)

clean:
	rm -rf *.aux *.bbl *.blg *.log *.pdf *.toc *.snm *.out *.nav *.dvi tags auto
