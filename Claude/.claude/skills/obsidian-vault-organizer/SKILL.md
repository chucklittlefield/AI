\---

name: obsidian-vault-organizer

description: Organize an Obsidian reference vault by moving notes into categorized subfolders, updating a summary index file, and enriching every note with frontmatter properties (category, review, description).

allowed-tools:

&#x20; - Read

&#x20; - Write

&#x20; - Edit

&#x20; - Bash

&#x20; - TodoWrite

&#x20; - AskUserQuestion

\---



\# Obsidian Vault Organizer



\## PURPOSE



Automate the full organization of an Obsidian reference/tool vault. Given a flat folder of markdown notes and an optional summary index file, this skill will:



1\. Propose meaningful subfolders based on the content and purpose of each note

2\. Move all notes into those subfolders

3\. Update a summary/index markdown file to reflect the new structure

4\. Add `category`, `review`, and `description` frontmatter properties to every note

5\. Create an Obsidian `.base` file at the vault root for a live table view



Use this when:

\- A user has a flat folder of Obsidian notes that need organizing

\- Notes have grown and categorization would improve navigation

\- The user wants consistent frontmatter properties across all notes



\---



\## STEP 1 — CLARIFY WITH THE USER



Before doing anything, use `AskUserQuestion` to confirm key details:



1\. What is the path to the vault folder?

2\. Is there a summary/index markdown file with tables describing each note? If so, what is its name?

3\. Should Claude propose the subfolder categories, or does the user have specific categories in mind?



If the user has a summary file with `| \[\[NoteLink]] | Description |` tables, the skill can auto-extract descriptions and use the section headings as category candidates.



\---



\## STEP 2 — SCAN THE FOLDER



List all `.md` files in the root of the target folder (not recursively — only the flat root level):



```bash

ls /path/to/vault/

```



Read the summary/index file if one exists. Parse out:

\- \*\*Table rows\*\*: `| \[\[ToolName]] | Description |` → extract tool name + description

\- \*\*Bullet references\*\*: `- \[\[NoteName]] — Description` → extract note name + description



Build a mental map of all notes and their purposes.



\---



\## STEP 3 — PROPOSE SUBFOLDER CATEGORIES



Based on the content of the notes (filenames, any available descriptions), propose a set of subfolders. Present these to the user before creating anything and ask for confirmation.



Good category examples for a cybersecurity vault:

\- `Reconnaissance` — scanning, enumeration, discovery tools

\- `Active Directory` — AD attack/enum tools

\- `Privilege Escalation` — privesc tools and reference guides

\- `Web Application` — web attack tools and techniques

\- `Password Attacks` — cracking, brute-force, credential capture

\- `Tunneling \& Pivoting` — network pivoting and tunneling

\- `Exploitation` — exploit frameworks and shellcode tools

\- `Scripting \& Utilities` — general-purpose scripts and CLI tools

\- `OSINT \& Git Recon` — open-source intelligence

\- `Network Infrastructure` — network/cloud infrastructure tools

\- `Methodology \& Reporting` — methodology notes, checklists, reporting



Adapt categories to the user's domain. The categories should reflect \*\*how the notes are used\*\*, not just the tool type.



\---



\## STEP 4 — CREATE SUBFOLDERS AND MOVE FILES



Once the user approves the category structure, create the folders and move files:



```bash

BASE="/path/to/vault"



\# Create folders

mkdir -p "$BASE/Category One"

mkdir -p "$BASE/Category Two"

\# ... etc.



\# Move files

mv "$BASE/SomeTool.md" "$BASE/Category One/"

mv "$BASE/AnotherTool.md" "$BASE/Category Two/"

\# ... etc.

```



\*\*Key rules:\*\*

\- Keep any root-level summary/index `.md` files in the root — do not move them into subfolders

\- Keep `.docx`, `.pdf`, and other non-note files in the root unless they clearly belong in a subfolder

\- After moving files out of any legacy catch-all folders (e.g., `Tactics/`, `Misc/`), remove those folders if they are now empty:

&#x20; ```bash

&#x20; rmdir "$BASE/OldFolder"

&#x20; ```

\- If `rmdir` fails with "Operation not permitted", use `mcp\_\_cowork\_\_allow\_cowork\_file\_delete` to get permission, then retry.



\---



\## STEP 5 — UPDATE THE SUMMARY/INDEX FILE



If a summary file exists, reorganize its sections to match the new subfolder structure:



\- Rename/reorder section headings to match folder names

\- Move tool entries into the correct sections

\- Remove duplicate entries (a tool listed in two sections should appear only once)

\- Add entries for any notes that were in sub-folders like `Tactics/` and are now promoted

\- Add a vault structure overview callout near the top, e.g.:



```markdown

> \*\*Vault Structure:\*\* `Reconnaissance/` · `Active Directory/` · `Privilege Escalation/` · ...

```



\- Update the `date modified` frontmatter field

\- Add a comment at the bottom noting the reorganization date



\*\*Important for Obsidian wikilinks:\*\* Obsidian resolves `\[\[NoteName]]` by filename globally across the vault. Moving files does \*\*not\*\* break wikilinks as long as filenames are unique — you do not need to update link paths, only reorganize the sections.



\---



\## STEP 6 — ADD `category` PROPERTY TO ALL NOTES



Write a Python script that adds `category: <FolderName>` to the YAML frontmatter of every `.md` file in each subfolder.



```python

import os, re



BASE = "/path/to/vault"

FOLDERS = \["Category One", "Category Two", ...]  # match actual folder names



for folder in FOLDERS:

&#x20;   folder\_path = os.path.join(BASE, folder)

&#x20;   for fname in os.listdir(folder\_path):

&#x20;       if not fname.endswith(".md"):

&#x20;           continue

&#x20;       fpath = os.path.join(folder\_path, fname)

&#x20;       with open(fpath, "r", encoding="utf-8") as f:

&#x20;           content = f.read()



&#x20;       # Skip if already has category

&#x20;       if re.search(r"^category:", content, re.MULTILINE):

&#x20;           continue



&#x20;       # Insert before closing --- of existing frontmatter

&#x20;       if content.startswith("---"):

&#x20;           end = content.find("---", 3)

&#x20;           if end != -1:

&#x20;               content = content\[:end] + f"category: {folder}\\n" + content\[end:]

&#x20;       else:

&#x20;           # No frontmatter — add it

&#x20;           content = f"---\\ncategory: {folder}\\n---\\n\\n" + content



&#x20;       with open(fpath, "w", encoding="utf-8") as f:

&#x20;           f.write(content)

```



\---



\## STEP 7 — ADD `review` PROPERTY TO ALL NOTES



A note needs review (`review: true`) if its body is empty or contains only headings. Notes with real content get `review: false`.



\*\*Body content detection logic:\*\*

1\. Strip the YAML frontmatter (everything between the first and second `---`)

2\. Split remaining text into lines; strip whitespace

3\. Filter out blank lines and lines that are purely headings (`# Heading`)

4\. If no non-heading lines remain → `review: true`; otherwise → `review: false`



```python

import os, re



BASE = "/path/to/vault"

FOLDERS = \[...]



def has\_body\_content(content):

&#x20;   if content.startswith("---"):

&#x20;       end = content.find("---", 3)

&#x20;       body = content\[end + 3:] if end != -1 else content

&#x20;   else:

&#x20;       body = content

&#x20;   non\_heading = \[

&#x20;       l.strip() for l in body.splitlines()

&#x20;       if l.strip() and not re.match(r'^#{1,6}\\s+', l.strip())

&#x20;   ]

&#x20;   return len(non\_heading) > 0



def add\_or\_update\_property(content, key, value):

&#x20;   content = re.sub(rf'^{re.escape(key)}:.\*\\n', '', content, flags=re.MULTILINE)

&#x20;   if content.startswith("---"):

&#x20;       end = content.find("---", 3)

&#x20;       if end != -1:

&#x20;           return content\[:end] + f"{key}: {str(value).lower()}\\n" + content\[end:]

&#x20;   return f"---\\n{key}: {str(value).lower()}\\n---\\n\\n" + content



for folder in FOLDERS:

&#x20;   for fname in os.listdir(os.path.join(BASE, folder)):

&#x20;       if not fname.endswith(".md"):

&#x20;           continue

&#x20;       fpath = os.path.join(BASE, folder, fname)

&#x20;       content = open(fpath).read()

&#x20;       review = not has\_body\_content(content)

&#x20;       open(fpath, "w").write(add\_or\_update\_property(content, "review", review))

```



\---



\## STEP 8 — ADD `description` PROPERTY FROM SUMMARY FILE



Parse descriptions from the summary file and write them into each note's frontmatter.



\*\*Parsing patterns:\*\*



```python

import re



\# Table rows:  | \[\[Target\\|Display]] | Description |

TABLE\_RE = re.compile(

&#x20;   r'^\\|\\s\*\\\[\\\[(\[^\\]|]+?)(?:\\\\?\\|\[^\\]]+?)?\\]\\]\\s\*\\|\\s\*(.+?)\\s\*\\|?\\s\*$',

&#x20;   re.MULTILINE

)



\# Bullet references:  - \[\[Target]] — Description

BULLET\_RE = re.compile(

&#x20;   r'^\[-\*]\\s+\\\[\\\[(\[^\\]|]+?)(?:\\\\?\\|\[^\\]]+?)?\\]\\]\\s+\[—–-]+\\s+(.+)$',

&#x20;   re.MULTILINE

)



descriptions = {}

for m in TABLE\_RE.finditer(summary\_content):

&#x20;   descriptions\[m.group(1).strip()] = m.group(2).strip()

for m in BULLET\_RE.finditer(summary\_content):

&#x20;   descriptions\[m.group(1).strip()] = m.group(2).strip()

```



\*\*Matching descriptions to files:\*\*

\- Build a dict of `{filename\_stem.lower(): full\_path}` for all `.md` files in subfolders

\- For each parsed description key, look up `key.lower()` in that dict

\- Special case: if a wikilink target ends in `.md` (e.g., `Enumerate Active Directory.ps1.md`), the actual file may be `Enumerate Active Directory.ps1.md.md` — also try `(key + ".md").lower()`



\*\*Writing the property:\*\*

```python

def yaml\_quote(s):

&#x20;   s = s.replace('\\\\', '\\\\\\\\').replace('"', '\\\\"')

&#x20;   return f'"{s}"'



\# Add to frontmatter using the same add\_or\_update\_property() function from Step 7

new\_content = add\_or\_update\_property(content, "description", yaml\_quote(desc\_text))

```



\---



\## STEP 9 — CREATE AN OBSIDIAN `.base` FILE



Create a `<VaultName>.base` file at the vault root. This gives users a live table view of all notes with their category, review status, and description.



```json

{

&#x20; "filters": {

&#x20;   "operator": "and",

&#x20;   "conditions": \[

&#x20;     {

&#x20;       "property": "category",

&#x20;       "operator": "is-not-empty",

&#x20;       "value": ""

&#x20;     }

&#x20;   ]

&#x20; },

&#x20; "sort": \[

&#x20;   { "property": "category", "direction": "asc" },

&#x20;   { "property": "file", "direction": "asc" }

&#x20; ],

&#x20; "columns": \[

&#x20;   { "id": "file",        "type": "file",     "width": 300 },

&#x20;   { "id": "category",   "type": "text",     "width": 200 },

&#x20;   { "id": "review",     "type": "checkbox", "width": 100 },

&#x20;   { "id": "description","type": "text",     "width": 400 }

&#x20; ]

}

```



The filter `category is-not-empty` ensures only the organized notes appear — root-level files like the summary itself are excluded.



\---



\## STEP 10 — VERIFY



Run a final verification:



```python

import os, re



BASE = "/path/to/vault"

FOLDERS = \[...]



all3 = missing = 0

for root, dirs, files in os.walk(BASE):

&#x20;   if root == BASE:

&#x20;       continue

&#x20;   for fname in files:

&#x20;       if not fname.endswith(".md"):

&#x20;           continue

&#x20;       text = open(os.path.join(root, fname)).read()

&#x20;       has\_d = bool(re.search(r'^description:', text, re.M))

&#x20;       has\_c = bool(re.search(r'^category:', text, re.M))

&#x20;       has\_r = bool(re.search(r'^review:', text, re.M))

&#x20;       if has\_d and has\_c and has\_r:

&#x20;           all3 += 1

&#x20;       else:

&#x20;           missing += 1

&#x20;           print(f"INCOMPLETE: {fname}")



print(f"Complete: {all3}  |  Missing properties: {missing}")

```



Report the result to the user and flag any notes that could not be matched to a description.



\---



\## OUTPUT



At the end of this skill, the vault will have:



\- \*\*Organized subfolders\*\* with all notes moved in

\- \*\*Updated summary/index file\*\* with sections matching folder names

\- \*\*`category` property\*\* on every note (matches its folder name)

\- \*\*`review` property\*\* on every note (`true` = empty body, `false` = has content)

\- \*\*`description` property\*\* on every note (sourced from the summary tables/bullets)

\- \*\*`.base` file\*\* at the vault root for a live Obsidian database view



\## NOTES



\- Obsidian wikilinks `\[\[NoteName]]` resolve by filename globally — moving files does not break links as long as filenames remain unique in the vault

\- The `review: true` flag is a quick way to find stubs that need content added

\- The `.base` file requires Obsidian 1.8+ with the Bases feature enabled

\- If a file cannot be matched to a description (no entry in the summary), it is skipped and reported — do not invent descriptions

