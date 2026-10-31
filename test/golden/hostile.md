# Row level security report

| Item | Value |
|---|---|
| Tool | tool\-name \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\r\\n\# FORGED heading \| a \| b \|\\r\\n&gt; FORGED quote\\r\\n\- FORGED item\\r\\n1\. FORGED number\\r\\n\-\-\-\\r\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\r\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\r\\n\\x1B\[31mred… |
| Checked | 4 tables or views |
| Input files read | 1 |
| Database used | a throwaway PostgreSQL database (version pg\-version \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\n\# FORGED heading \| a \| b \|\\n&gt; FORGED quote\\n\- FORGED item\\n1\. FORGED number\\n\-\-\-\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\n\\x1B\[31mred\\x1B\[0m \\x1B\]8;;ht…, docker image image \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\r\\n\# FORGED heading \| a \| b \|\\r\\n&gt; FORGED quote\\r\\n\- FORGED item\\r\\n1\. FORGED number\\r\\n\-\-\-…) |
| Run complete | **NO**, results may be partial |
| Tests run | 4 (2 showed a real problem) |
| PROVEN | 2 |
| SUSPECTED | 1 |
| INCONCLUSIVE | 1 |
| CLEAN | 1 |

## Result

**2 PROVEN, 1 SUSPECTED, 1 INCONCLUSIVE, 1 CLEAN**

2 of 4 checked tables or views could be attacked successfully against a real database. PROVEN means we reproduced the problem ourselves. 2 more need a look: SUSPECTED and INCONCLUSIVE items are NOT proven and carry low confidence. The run is incomplete, so results may be partial.

## What we found

### 1. PROVEN · critical · ``````subject \u{D800}\u{202E}\u{200B} `one` ``two`` ```three```` four`````  # FORGED heading | a | b |  > FORGED quote  - FORGED item  1. FORGED number  ---  <scrip…``````

**finding\-title \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\r\\n\# FORGED heading \| a \| b \|\\r\\n&gt; FORGED quote\\r\\n\- FORGED item\\r\\n1\. FORGED number\\r\\n\-\-\-\\r\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\r\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\r\\n\\x1B\[31mre…**

**An attacker could:** attacker\-can \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\n\# FORGED heading \| a \| b \|\\n&gt; FORGED quote\\n\- FORGED item\\n1\. FORGED number\\n\-\-\-\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\n\\x1B\[31mred\\x1B\[0m \\x1B\]8;;…

Kind: table. PROVEN: reproduced against a real database.

#### Why

- cause\-text \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\n\# FORGED heading \| a \| b \|\\n&gt; FORGED quote\\n\- FORGED item\\n1\. FORGED number\\n\-\-\-\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\n\\x1B\[31mred\\x1B\[0m \\x1B\]8;;ht…

#### How we proved it

**Check 1.** We acted as an anonymous visitor (no login, only the public key) and ran:

`````sql
select 'proof-sql'; -- \x1B[2J\u{202E}\u{200B}\x00
```
# FORGED heading
````sql
<b>x</b>	end
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB…
`````

Result: the access policy let the row through; only a table constraint stopped it (error sqlstate \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\n\# FORGED heading \| a \| b \|\\n&gt; FORGED quote\\n\- FORGED item\\n1\. FORGED number\\n\-\-\-\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\n\\x1B\[31mred\\x1B\[0m \\x1B\]8;;http…: db\-message \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\n\# FORGED heading \| a \| b \|\\n&gt; FORGED quote\\n\- FORGED item\\n1\. FORGED number\\n\-\-\-\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\n\\x1B\[31mred\\x1B\[0m \\x1B\]8;;ht…). Access was ALLOWED. That is the problem.

Evidence: `sha256 3b5fc140837e`

2\. The evidence record ``````missing-probe-id \u{D800}\u{202E}\u{200B} `one` ``two`` ```three```` four````` # FORGED heading | a | b | > FORGED quote - FORGED item 1. FORGED number --- <sc…`````` is missing from this report.

#### Attempts the database blocked

- probe\-title \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\r\\n\# FORGED heading \| a \| b \|\\r\\n&gt; FORGED quote\\r\\n\- FORGED item\\r\\n1\. FORGED number\\r\\n\-\-\-\\r\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\r\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\r\\n\\x1B\[31mred…: the database ran it but changed 0 rows (1 row seeded for this test)

#### Could not be tested (no clear answer)

- probe\-title \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\r\\n\# FORGED heading \| a \| b \|\\r\\n&gt; FORGED quote\\r\\n\- FORGED item\\r\\n1\. FORGED number\\r\\n\-\-\-\\r\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\r\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\r\\n\\x1B\[31mred…: inconclusive\-reason \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\r\\n\# FORGED heading \| a \| b \|\\r\\n&gt; FORGED quote\\r\\n\- FORGED item\\r\\n1\. FORGED number\\r\\n\-\-\-\\r\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\r\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\r\\n\\x1B…

### 2. PROVEN · high · ``````view \u{D800}\u{202E}\u{200B} `one` ``two`` ```three```` four````` # FORGED heading | a | b | > FORGED quote - FORGED item 1. FORGED number --- <script>alert(1…``````

**view\-title \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\n\# FORGED heading \| a \| b \|\\n&gt; FORGED quote\\n\- FORGED item\\n1\. FORGED number\\n\-\-\-\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\n\\x1B\[31mred\\x1B\[0m \\x1B\]8;;ht…**

**An attacker could:** view\-attacker\-can \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\r\\n\# FORGED heading \| a \| b \|\\r\\n&gt; FORGED quote\\r\\n\- FORGED item\\r\\n1\. FORGED number\\r\\n\-\-\-\\r\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\r\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\r\\n\\x1B\[3…

Kind: view. PROVEN: reproduced against a real database.

#### How we proved it

**Check 1.** We acted as an anonymous visitor (no login, only the public key) and ran:

`````sql
select 'proof-sql'; -- \x1B[2J\u{202E}\u{200B}\x00
```
# FORGED heading
````sql
<b>x</b>	end
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB…
`````

Result: the database returned 2 rows (1 row seeded for this test). Access was ALLOWED. That is the problem. Proof\-reason \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\n\# FORGED heading \| a \| b \|\\n&gt; FORGED quote\\n\- FORGED item\\n1\. FORGED number\\n\-\-\-\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\n\\x1B\[31mred\\x1B\[0m \\x1B\]8;;…

Evidence: `sha256 83f73d379ddc`

### 3. SUSPECTED · medium · ``````suspect-subject \u{D800}\u{202E}\u{200B} `one` ``two`` ```three```` four`````  # FORGED heading | a | b |  > FORGED quote  - FORGED item  1. FORGED number  ---…``````

**suspect\-title \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\r\\n\# FORGED heading \| a \| b \|\\r\\n&gt; FORGED quote\\r\\n\- FORGED item\\r\\n1\. FORGED number\\r\\n\-\-\-\\r\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\r\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\r\\n\\x1B\[31mre…**

> **NOT proven.** Reading the SQL suggests a problem, but the database did not confirm it. Treat this as a lead to check, not as a fact.

**An attacker could:** suspect\-attacker\-can \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\n\# FORGED heading \| a \| b \|\\n&gt; FORGED quote\\n\- FORGED item\\n1\. FORGED number\\n\-\-\-\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\n\\x1B\[31mred\\x1B\[0m …

Kind: table. SUSPECTED: NOT proven, low confidence.

#### Why

- suspect\-cause \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\r\\n\# FORGED heading \| a \| b \|\\r\\n&gt; FORGED quote\\r\\n\- FORGED item\\r\\n1\. FORGED number\\r\\n\-\-\-\\r\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\r\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\r\\n\\x1B\[31mre…

## Looked fine

- ``````clean-subject \u{D800}\u{202E}\u{200B} `one` ``two`` ```three```` four`````  # FORGED heading | a | b |  > FORGED quote  - FORGED item  1. FORGED number  ---  …``````: clean\-title \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\r\\n\# FORGED heading \| a \| b \|\\r\\n&gt; FORGED quote\\r\\n\- FORGED item\\r\\n1\. FORGED number\\r\\n\-\-\-\\r\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\r\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\r\\n\\x1B\[31mred…

## How to fix

- ``````subject \u{D800}\u{202E}\u{200B} `one` ``two`` ```three```` four`````  # FORGED heading | a | b |  > FORGED quote  - FORGED item  1. FORGED number  ---  <scrip…``````: A fix was proposed but is not yet confirmed. fix\-note \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\n\# FORGED heading \| a \| b \|\\n&gt; FORGED quote\\n\- FORGED item\\n1\. FORGED number\\n\-\-\-\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\n\\x1B\[31mred\\x1B\[0m \\x1B\]8;;http…
- ``````view \u{D800}\u{202E}\u{200B} `one` ``two`` ```three```` four````` # FORGED heading | a | b | > FORGED quote - FORGED item 1. FORGED number --- <script>alert(1…``````: A fix needs a decision from you (see below). view\-fix\-note \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\r\\n\# FORGED heading \| a \| b \|\\r\\n&gt; FORGED quote\\r\\n\- FORGED item\\r\\n1\. FORGED number\\r\\n\-\-\-\\r\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\r\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\r\\n\\x1B\[31mre…
- ``````suspect-subject \u{D800}\u{202E}\u{200B} `one` ``two`` ```three```` four`````  # FORGED heading | a | b |  > FORGED quote  - FORGED item  1. FORGED number  ---…``````: No fix was proposed automatically. suspect\-fix\-note \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\n\# FORGED heading \| a \| b \|\\n&gt; FORGED quote\\n\- FORGED item\\n1\. FORGED number\\n\-\-\-\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\n\\x1B\[31mred\\x1B\[0m \\x1B…

### Proposed SQL (starting point, review before use)

`````sql
select 'fix-sql'; -- \x1B[2J\u{202E}\u{200B}\x00
```
# FORGED heading
````sql
<b>x</b>	end
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB…
`````

### These need a decision only you can make

- ``````view \u{D800}\u{202E}\u{200B} `one` ``two`` ```three```` four````` # FORGED heading | a | b | > FORGED quote - FORGED item 1. FORGED number --- <script>alert(1…``````: decision\-reason \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\r\\n\# FORGED heading \| a \| b \|\\r\\n&gt; FORGED quote\\r\\n\- FORGED item\\r\\n1\. FORGED number\\r\\n\-\-\-\\r\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\r\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\r\\n\\x1B\[31m…

## Fix check

**PARTIAL**: only some tables are fixed and confirmed. See the table below. The rest still need work.

Fix statements the database rejected: 1

- `````select 'apply-statement'; -- \x1B[2J\u{202E}\u{200B}\x00 ``` # FORGED heading ````sql <b>x</b>\x09end BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB…````` apply\-sqlstate \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\n\# FORGED heading \| a \| b \|\\n&gt; FORGED quote\\n\- FORGED item\\n1\. FORGED number\\n\-\-\-\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\n\\x1B\[31mred\\x1B\[0m \\x1B\]8… apply\-message \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\r\\n\# FORGED heading \| a \| b \|\\r\\n&gt; FORGED quote\\r\\n\- FORGED item\\r\\n1\. FORGED number\\r\\n\-\-\-\\r\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\r\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\r\\n\\x1B\[31mre…

| Table | Result | Closed | Still works | Normal use broken | No clear answer | Because |
|---|---|---|---|---|---|---|
| subject \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\r\\n\# FORGED heading \| a \| b \|\\r\\n&gt; FORGED quote\\r\\n\- FORGED item\\r\\n1\. FORGED number\\r\\n\-\-\-\\r\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\r\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\r\\n\\x1B\[31mred\\x1B\[… | VERIFIED (attacks closed, normal use works) | probe\-title \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\r\\n\# FORGED heading \| a \| b \|\\r\\n&gt; FORGED quote\\r\\n\- FORGED item\\r\\n1\. FORGED number\\r\\n\-\-\-\\r\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\r\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\r\\n\\x1B\[31mred… | probe\-title \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\r\\n\# FORGED heading \| a \| b \|\\r\\n&gt; FORGED quote\\r\\n\- FORGED item\\r\\n1\. FORGED number\\r\\n\-\-\-\\r\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\r\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\r\\n\\x1B\[31mred… | probe\-title \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\r\\n\# FORGED heading \| a \| b \|\\r\\n&gt; FORGED quote\\r\\n\- FORGED item\\r\\n1\. FORGED number\\r\\n\-\-\-\\r\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\r\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\r\\n\\x1B\[31mred… | probe\-title \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\r\\n\# FORGED heading \| a \| b \|\\r\\n&gt; FORGED quote\\r\\n\- FORGED item\\r\\n1\. FORGED number\\r\\n\-\-\-\\r\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\r\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\r\\n\\x1B\[31mred… | verification\-reason \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\r\\n\# FORGED heading \| a \| b \|\\r\\n&gt; FORGED quote\\r\\n\- FORGED item\\r\\n1\. FORGED number\\r\\n\-\-\-\\r\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\r\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\r\\n\\x1B… |
| view \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\n\# FORGED heading \| a \| b \|\\n&gt; FORGED quote\\n\- FORGED item\\n1\. FORGED number\\n\-\-\-\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\n\\x1B\[31mred\\x1B\[0m \\x1B\]8;;http\://e… | NO FIX PROPOSED | none | none | none | none | verification\-reason\-2 \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\r\\n\# FORGED heading \| a \| b \|\\r\\n&gt; FORGED quote\\r\\n\- FORGED item\\r\\n1\. FORGED number\\r\\n\-\-\-\\r\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\r\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\r\\n… |

## Static auditor cross-check

Findings from audit\-tool \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\n\# FORGED heading \| a \| b \|\\n&gt; FORGED quote\\n\- FORGED item\\n1\. FORGED number\\n\-\-\-\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\n\\x1B\[31mred\\x1B\[0m \\x1B\]8;;ht… audit\-version \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\r\\n\# FORGED heading \| a \| b \|\\r\\n&gt; FORGED quote\\r\\n\- FORGED item\\r\\n1\. FORGED number\\r\\n\-\-\-\\r\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\r\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\r\\n\\x1B\[31mre… (project audit\-project \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\r\\n\# FORGED heading \| a \| b \|\\r\\n&gt; FORGED quote\\r\\n\- FORGED item\\r\\n1\. FORGED number\\r\\n\-\-\-\\r\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\r\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\r\\n\\x1B\[31mre…), checked against our tests:

| Result | Finding | Rule | Severity | Location | Table | Note |
|---|---|---|---|---|---|---|
| PROVEN by our test | audit\-title \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\r\\n\# FORGED heading \| a \| b \|\\r\\n&gt; FORGED quote\\r\\n\- FORGED item\\r\\n1\. FORGED number\\r\\n\-\-\-\\r\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\r\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\r\\n\\x1B\[31mred… | audit\-rule \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\n\# FORGED heading \| a \| b \|\\n&gt; FORGED quote\\n\- FORGED item\\n1\. FORGED number\\n\-\-\-\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\n\\x1B\[31mred\\x1B\[0m \\x1B\]8;;ht… | audit\-severity \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\n\# FORGED heading \| a \| b \|\\n&gt; FORGED quote\\n\- FORGED item\\n1\. FORGED number\\n\-\-\-\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\n\\x1B\[31mred\\x1B\[0m \\x1B\]8… | audit\-file \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\n\# FORGED heading \| a \| b \|\\n&gt; FORGED quote\\n\- FORGED item\\n1\. FORGED number\\n\-\-\-\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\n\\x1B\[31mred\\x1B\[0m \\x1B\]8;;ht… | audit\-table \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\r\\n\# FORGED heading \| a \| b \|\\r\\n&gt; FORGED quote\\r\\n\- FORGED item\\r\\n1\. FORGED number\\r\\n\-\-\-\\r\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\r\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\r\\n\\x1B\[31mred… | audit\-note \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\n\# FORGED heading \| a \| b \|\\n&gt; FORGED quote\\n\- FORGED item\\n1\. FORGED number\\n\-\-\-\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\n\\x1B\[31mred\\x1B\[0m \\x1B\]8;;ht… |

1 static finding out of scope (not about row level security, not tested here).

- audit\-warning \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\r\\n\# FORGED heading \| a \| b \|\\r\\n&gt; FORGED quote\\r\\n\- FORGED item\\r\\n1\. FORGED number\\r\\n\-\-\-\\r\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\r\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\r\\n\\x1B\[31mre…

## Migration statements the database rejected

1 in total. Anything after them may not have been tested as written.

- ``````error-file \u{D800}\u{202E}\u{200B} `one` ``two`` ```three```` four````` # FORGED heading | a | b | > FORGED quote - FORGED item 1. FORGED number --- <script>a…`````` error\-sqlstate \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\n\# FORGED heading \| a \| b \|\\n&gt; FORGED quote\\n\- FORGED item\\n1\. FORGED number\\n\-\-\-\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\n\\x1B\[31mred\\x1B\[0m \\x1B\]8… error\-message \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\r\\n\# FORGED heading \| a \| b \|\\r\\n&gt; FORGED quote\\r\\n\- FORGED item\\r\\n1\. FORGED number\\r\\n\-\-\-\\r\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\r\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\r\\n\\x1B\[31mre…: `````select 'error-statement'; -- \x1B[2J\u{202E}\u{200B}\x00 ``` # FORGED heading ````sql <b>x</b>\x09end BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB…`````

## Test data problems

- ``````seed-table \u{D800}\u{202E}\u{200B} `one` ``two`` ```three```` four````` # FORGED heading | a | b | > FORGED quote - FORGED item 1. FORGED number --- <script>a…``````: failed (seed\-reason \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\r\\n\# FORGED heading \| a \| b \|\\r\\n&gt; FORGED quote\\r\\n\- FORGED item\\r\\n1\. FORGED number\\r\\n\-\-\-\\r\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\r\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\r\\n\\x1B\[31mred…)

## Warnings

- warning \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\r\\n\# FORGED heading \| a \| b \|\\r\\n&gt; FORGED quote\\r\\n\- FORGED item\\r\\n1\. FORGED number\\r\\n\-\-\-\\r\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\r\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\r\\n\\x1B\[31mred\\x1B\[…

## What was not checked

- not\-checked \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\r\\n\# FORGED heading \| a \| b \|\\r\\n&gt; FORGED quote\\r\\n\- FORGED item\\r\\n1\. FORGED number\\r\\n\-\-\-\\r\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\r\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\r\\n\\x1B\[31mred…

## Inputs

| File | Bytes | sha256 |
|---|---|---|
| input\-path \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\n\# FORGED heading \| a \| b \|\\n&gt; FORGED quote\\n\- FORGED item\\n1\. FORGED number\\n\-\-\-\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\n\\x1B\[31mred\\x1B\[0m \\x1B\]8;;ht… | 10 | input\-sha \\u\{D800\}\\u\{202E\}\\u\{200B\} \`one\` \`\`two\`\` \`\`\`three\`\`\`\` four\`\`\`\`\`\\r\\n\# FORGED heading \| a \| b \|\\r\\n&gt; FORGED quote\\r\\n\- FORGED item\\r\\n1\. FORGED number\\r\\n\-\-\-\\r\\n&lt;script&gt;alert\(1\)&lt;/script&gt; &lt;img src\=x onerror\=alert\(1\)&gt; &amp;amp; &amp;lt;b&amp;gt;\\r\\n\[FORGED link\]\(javascript\:alert\(1\)\) \!\[FORGED image\]\(http\://evil\.example/x\.png\) \@everyone https\://evil\.example www\.evil\.example a\@evil\.example\\r\\n\\x1B\[31mred… |
