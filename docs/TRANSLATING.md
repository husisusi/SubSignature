# Translating SubSignature

SubSignature uses the English UI text itself as the translation key (gettext style). Every language is one JSON file in `public_html/lang/`:

```json
{
  "@meta": { "code": "de", "name": "Deutsch", "dir": "ltr" },
  "Create account": "Konto erstellen",
  "Created {count} signatures": "{count} Signaturen erstellt"
}
```

* English is built in. `en.json` is only a master catalogue (all keys, identity values) that the tools compare against.
* A key that is missing in a language falls back to English, so a partial translation is safe.
* `{name}` placeholders must be kept exactly as they are; you may move them within the sentence.
* `\n` in a value is a line break.
* Do not translate technical samples such as `smtp.example.com`, `data.csv` or user names.

## Tooling

Run from the project root (PHP CLI only, no network needed):

```bash
php tools/i18n.php extract        # rebuild lang/en.json from the source code
php tools/i18n.php check          # coverage, unused keys, placeholder mismatches per language
php tools/i18n.php check -v       # ... plus the list of missing keys
php tools/i18n.php new sv         # create lang/sv.json (all keys, empty values)
php tools/i18n.php sync           # add newly found keys (empty) to every language file
```

## Adding a language

1. `php tools/i18n.php new <code>` (for example `sv`, `cs`, `vi`).
2. Translate the values in `public_html/lang/<code>.json`. Leave a value empty (or remove the key) to fall back to English.
3. Edit the `@meta` block at the top of the file: `"name"` is the language's own name as shown in the menu (for example `"Svenska"`), `"dir"` is `"rtl"` for right-to-left languages, otherwise `"ltr"`. As soon as the name is set the language shows up in the menu, no code change needed. (Languages that ship with the application are listed in `builtinLanguages()` in `includes/i18n.php`; their `@meta` is ignored. Shipped languages: `en`, `de`, `es`, `fr`, `it`, `pt`, `nl`, `pl`, `tr`, `ru`, `uk`, `ar`, `hi`, `id`, `zh`, `ja`, `ko` and `bs` = Bosanski, 18 in total.)
4. If the editor (Jodit) needs a different locale code, add it to the map in `template_editor.php` (currently `zh` -> `zh_cn`, `pt` -> `pt_br`).
5. `php tools/i18n.php check` must report `0 placeholder mismatches`.
6. Open the pages in the new language, in light and dark mode, and check long texts in the sidebar and buttons.

## Using translations in code

| Function | Use |
|----------|-----|
| `t('Text {n}', ['n' => 3])` | plain text (for PHP strings, flash messages, mail) |
| `et('Text')` | escaped for HTML output (parameters are escaped too) |
| `eth('Click {link}', ['link' => $trustedHtml])` | escaped text with trusted HTML parameters |
| `tj('Text')` | JSON string literal for inline JavaScript |

After adding or changing texts run `php tools/i18n.php extract` and `sync`.
