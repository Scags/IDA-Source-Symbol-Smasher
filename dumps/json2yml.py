import json
import yaml
import sys

def main():
	for i in xrange(len(sys.argv)):
		if i == 0:
			continue
		with open(sys.argv[i], "r") as f:
			j = json.load(f)

		with open(sys.argv[i].replace("json", "yml"), "w") as f:
			yaml.safe_dump(j, f, default_flow_style = False, width = 999999)

if __name__ == "__main__":
	main()