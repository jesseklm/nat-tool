all: main.py

clean:
	rm -f *.py

%.py: %.ui
	pyside6-uic $< -o $@
