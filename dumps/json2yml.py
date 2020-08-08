import json
import yaml
import sys

def main():
	with open(sys.argv[1], "r") as f:
		j = json.load(f)

	with open(sys.argv[1].replace("json", "yml"), "w") as f:
		yaml.safe_dump(j, f, default_flow_style = False, width = 999999)

if __name__ == "__main__":
	main()