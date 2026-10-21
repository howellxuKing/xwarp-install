"""Validate fixed private release metadata before passing references to the shell."""
import argparse,json,shlex
from pathlib import Path
from upgrade import validate_image

def references(manifest):
    if manifest.get("format")!=1 or manifest.get("platform")!="linux/amd64":
        raise ValueError("Unsupported release manifest")
    images=manifest["images"]
    expected={"backend":"ghcr.io/howellxuking/xwarp", "ui":"ghcr.io/howellxuking/xwarp-ui", "core":"jonssonyan/trojan-panel-core"}
    result={}
    for name,repository in expected.items():
        value=validate_image(images[name])
        if value.split("@",1)[0]!=repository: raise ValueError("Unexpected release image repository")
        result["XWARP_"+name.upper()+"_IMAGE"]=value
    return result

if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("manifest");args=parser.parse_args()
    for name,value in references(json.loads(Path(args.manifest).read_text())) .items():
        print(name+"="+shlex.quote(value))
