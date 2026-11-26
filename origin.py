from ipaddress import ip_address
import os
from pathlib import Path


config = Path("/tmp/home-rules-nginx.conf")
router = ip_address(os.environ["ORIGIN_ALLOWED_IP"])
template = Path(__file__).with_name("nginx.conf").read_text()
config.write_text(template.replace("@ROUTER_IP@", str(router)))
os.execvp("nginx", ["nginx", "-c", str(config), "-g", "daemon off;"])
