# recon-dradis
recon-dradis attempts to automate hostname reconaissance by running various tools to discover in-scope hostnames and automatically updating nodes in Dradis with this information. The following tools are currently supported (with more to come):
1. Sublist3r (https://github.com/aboul3la/Sublist3r)
## Warning
Please note that this tool is still in very early stages of development and may contain bugs. Please try it against a test/mock Dradis project to make sure you don't lose any important data in the event something goes wrong.
## Getting Started
1. Clone the repository (be sure to include `--recurse-submodules`):  
```
$ git clone --recurse-submodules https://github.com/njfox/recon-dradis && cd recon-dradis
```
2. Add your Dradis API key and URL to `dradis_config.json` (**note**: do not include the `/pro` or anything else in the path)  
#### IMPORTANT
3. Tell git to ignore further changes to `dradis_config.json` so you don't accidentally push secrets to GitHub:  
```
$ git update-index --assume-unchanged dradis_config.json
```
4. Open your Dradis project and upload your Nmap scan. `recon-dradis` assumes your nodes have been imported from an Nmap XML, are under the `plugin.output` root node, and contain a note with the following structure somewhere in it:
```
#[Hostnames]#
<hostnames discovered by Nmap, if any>

#[OS]#
```
You may need to edit the Nmap plugin settings in the plugin manager to create this structure.  

5. Run the tool. At minimum, you must specify a domain with `-d` and a Dradis project name with `-p`:
```
$ ./recon-dradis.py -d example.com -p "Example Penetration Test"
```
6. Optionally, you may specify a line-separated list of target domains with `-f`/`--domain-file`
```
$ ./recon-dradis.py -f domains.txt -p "Example Penetration Test"
```
7. You may also specify a line-separated list of in-scope network ranges with `-s`/`--scope-file`. Only IP addresses in these ranges will be modified in the Dradis project. If no scope file is defined, all IP addresses discovered will be considered in-scope.
```
$ ./recon-dradis.py -f domains.txt -s scope.txt -p "Example Penetration Test"
```
## Contributing
1. Create a new branch for your feature:  
```
$ git checkout -b my_new_feature
```
2. Make code changes and add commits
3. Push commits to the branch:  
```
$ git push origin my_new_feature
```
4. When your feature is complete, create a new Pull Request so it can be merged into `master`.