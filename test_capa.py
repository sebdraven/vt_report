import capa.main
from capa.main import compute_layout
import capa.rules
import capa.render.json
import sys

def main(path_file, path_rules, path_signatures):

    sigs = capa.main.get_signatures(path_signatures)
    rules = capa.main.get_rules([path_rules])
  
    capa_json = None
  
    extractor = capa.main.get_extractor(path_file, 'auto','windows','vivisect', sigs,disable_progress=True)
    capabilities, counts = capa.main.find_capabilities(rules, extractor, disable_progress=True)
    meta = capa.main.collect_metadata(sys.argv, path_file,'pe','windows', [path_rules], extractor)
    meta["analysis"].update(counts)
    meta["analysis"]["layout"] = compute_layout(rules, extractor, capabilities)
    capa_json=capa.render.json.render(meta, rules, capabilities)
    print(capa_json)
 
        

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2], sys.argv[3])