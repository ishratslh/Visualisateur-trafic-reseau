all : setup run
setup : 
	pip install tk |pip install wheel|pip install numpy|pip install pandas

run : 
	python3 graph2.py

clean:
	rm -rf __pycache__
