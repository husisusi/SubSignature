<?php
/**
 * includes/NotesDxl.php - converts a rendered signature (HTML) into Domino XML
 * rich text (DXL) for HCL Notes.
 *
 * Why: when Notes converts HTML/MIME into a rich-text signature itself, the
 * images become attachments and CSS and table layout are lost. A signature
 * that is written as DXL rich text through the Domino DXL importer is stored
 * exactly like one that a user set up by hand: pictures inline, tables, fonts
 * and links intact. The Domino agent fetches the result through the API
 * (GET /api/v1/signatures?notes=dxl) and imports it.
 *
 * What is converted:
 *   - text with font, size, bold/italic/underline/strike-through, colour
 *     (inline styles, <b>, <i>, <u>, <font>, <h1>-<h6> ...),
 *   - paragraphs and line breaks with alignment, indentation and spacing,
 *   - links (http, https, mailto, tel only),
 *   - pictures (PNG, JPEG, GIF), embedded with the same rules as the API's
 *     image embedding (see SignatureImages.php),
 *   - tables with column widths, cell borders (one border colour per table, a
 *     Notes limit), cell background colours, vertical alignment, column and
 *     row spans; layout-only tables are unwrapped,
 *   - horizontal rules and simple lists.
 * CSS from <style> blocks and classes is not applied (only inline styles and
 * HTML attributes), as in most mail clients.
 *
 * Security: the output is generated from scratch - element names are fixed,
 * every text and attribute value is escaped, colours, sizes and font names are
 * normalised, links are limited to http(s)/mailto/tel. Before it is returned,
 * the output is checked against the same element allow-list that the Domino
 * agent enforces, and parsed as XML. No input DXL is ever passed through.
 */

/** Raw image data embedded per signature (all pictures together). */
const NOTES_DXL_MAX_IMAGE_BYTES_TOTAL = 3145728;
/** Largest result (the Domino agent refuses anything above 4 MiB). */
const NOTES_DXL_MAX_BYTES = 4194304;
/** Font for text that has no font of its own. */
const NOTES_DXL_DEFAULT_FONT = 'Arial';
/** Size in points for text that has no size of its own. */
const NOTES_DXL_DEFAULT_SIZE = 10.0;
/** Nested tables deeper than this are flattened. */
const NOTES_DXL_MAX_TABLE_DEPTH = 5;
/** A table is never made wider than this (pixels at 96 dpi). */
const NOTES_DXL_MAX_TABLE_WIDTH = 900;
/** The only elements the result may contain (the Domino agent checks the same list). */
const NOTES_DXL_ALLOWED_ELEMENTS = [
    'richtext', 'pardef', 'par', 'run', 'font', 'break', 'tab', 'picture', 'png', 'gif', 'jpeg',
    'notesbitmap', 'urllink', 'table', 'tablecolumn', 'tablerow', 'tablecell', 'border', 'horizrule',
];

/**
 * True when the PHP DOM extension is available (needed for the conversion).
 */
function notesDxlAvailable(): bool
{
    return class_exists('DOMDocument') && function_exists('libxml_use_internal_errors');
}

/**
 * Converts a rendered, sanitised signature into DXL rich text.
 *
 * $resolveImage(string $src): array returns an entry like resolveSignatureImage()
 * (status "ok" with content_type and bytes, or another status).
 *
 * @return array{dxl: string, complete: bool, images_embedded: int,
 *               images_missing: array<int, array{src: string, status: string}>, warnings: string[]}
 * @throws RuntimeException when the result fails the final checks
 */
function signatureToNotesDxl(string $html, callable $resolveImage): array
{
    return (new NotesDxlConverter($resolveImage))->convert($html);
}

/**
 * Collects blocks (paragraphs and tables) for one container: the signature
 * itself or one table cell.
 */
final class NotesDxlFlow
{
    /** @var array<int, array> */
    public $blocks = [];
    /** @var array|null the paragraph that is being filled */
    public $par = null;
    /** @var string spacing requested for the next paragraph ("1", "1.5" or "2") */
    public $pendingBefore = '1';
}

final class NotesDxlConverter
{
    /** Elements that are skipped together with their content. */
    private const SKIP = [
        'head' => 1, 'style' => 1, 'script' => 1, 'title' => 1, 'meta' => 1, 'link' => 1, 'template' => 1,
        'noscript' => 1, 'iframe' => 1, 'object' => 1, 'embed' => 1, 'svg' => 1, 'math' => 1, 'button' => 1,
        'input' => 1, 'select' => 1, 'textarea' => 1, 'audio' => 1, 'video' => 1, 'canvas' => 1, 'map' => 1,
        'colgroup' => 1, 'col' => 1, 'base' => 1, 'wbr' => 1,
    ];

    /** Elements that start a paragraph of their own. */
    private const BLOCKS = [
        'p' => 1, 'div' => 1, 'h1' => 1, 'h2' => 1, 'h3' => 1, 'h4' => 1, 'h5' => 1, 'h6' => 1,
        'ul' => 1, 'ol' => 1, 'li' => 1, 'blockquote' => 1, 'center' => 1, 'address' => 1, 'section' => 1,
        'article' => 1, 'header' => 1, 'footer' => 1, 'nav' => 1, 'aside' => 1, 'main' => 1, 'figure' => 1,
        'figcaption' => 1, 'dl' => 1, 'dt' => 1, 'dd' => 1, 'pre' => 1, 'fieldset' => 1, 'details' => 1,
        'summary' => 1, 'caption' => 1, 'tr' => 1, 'td' => 1, 'th' => 1, 'tbody' => 1, 'thead' => 1,
        'tfoot' => 1, 'form' => 1, 'hgroup' => 1,
    ];

    /** Font sizes of <h1>..<h6> relative to the surrounding text. */
    private const HEADING_EM = ['h1' => 2.0, 'h2' => 1.5, 'h3' => 1.17, 'h4' => 1.0, 'h5' => 0.83, 'h6' => 0.67];

    /** Image statuses that may succeed on a later request. */
    private const TEMPORARY_IMAGE_STATUS = ['fetch_deferred' => 1, 'fetch_failed' => 1];

    private const NAMED_COLORS = [
        'black' => '#000000', 'white' => '#ffffff', 'red' => '#ff0000', 'green' => '#008000', 'blue' => '#0000ff',
        'yellow' => '#ffff00', 'gray' => '#808080', 'grey' => '#808080', 'silver' => '#c0c0c0', 'maroon' => '#800000',
        'navy' => '#000080', 'purple' => '#800080', 'teal' => '#008080', 'olive' => '#808000', 'lime' => '#00ff00',
        'aqua' => '#00ffff', 'cyan' => '#00ffff', 'fuchsia' => '#ff00ff', 'magenta' => '#ff00ff', 'orange' => '#ffa500',
        'darkgray' => '#a9a9a9', 'darkgrey' => '#a9a9a9', 'lightgray' => '#d3d3d3', 'lightgrey' => '#d3d3d3',
        'dimgray' => '#696969', 'dimgrey' => '#696969', 'gainsboro' => '#dcdcdc', 'whitesmoke' => '#f5f5f5',
        'darkblue' => '#00008b', 'darkgreen' => '#006400', 'darkred' => '#8b0000', 'steelblue' => '#4682b4',
        'royalblue' => '#4169e1', 'dodgerblue' => '#1e90ff', 'gold' => '#ffd700', 'pink' => '#ffc0cb',
        'brown' => '#a52a2a', 'crimson' => '#dc143c', 'indigo' => '#4b0082', 'slategray' => '#708090',
        'slategrey' => '#708090', 'darkslategray' => '#2f4f4f', 'darkslategrey' => '#2f4f4f', 'lightblue' => '#add8e6',
        'skyblue' => '#87ceeb', 'darkorange' => '#ff8c00', 'tomato' => '#ff6347', 'beige' => '#f5f5dc',
    ];

    /** @var callable */
    private $resolveImage;
    /** @var array<string, true> */
    private $warnings = [];
    /** @var array<int, array{src: string, status: string}> */
    private $missing = [];
    /** @var int */
    private $embedded = 0;
    /** @var int */
    private $imageBytes = 0;
    /** @var bool */
    private $complete = true;
    /** @var int */
    private $linkSeq = 0;
    /** @var int */
    private $listSeq = 0;
    /** @var array<int, true> list items whose marker was used already */
    private $listUsed = [];
    /** @var int */
    private $pardefSeq = 0;

    public function __construct(callable $resolveImage)
    {
        $this->resolveImage = $resolveImage;
    }

    public function convert(string $html): array
    {
        $root = $this->parse($html);
        $flow = new NotesDxlFlow();
        if ($root !== null) {
            $this->walkChildren($root, $this->rootContext(), $flow, 0);
        }
        $this->closePar($flow);
        if (!$flow->blocks) {
            $flow->blocks[] = ['type' => 'spacer', 'size' => (int)NOTES_DXL_DEFAULT_SIZE, 'indent' => 0.0];
        }

        $dxl = "<richtext>\n" . $this->serializeBlocks($flow->blocks, null) . "</richtext>\n";
        if (strlen($dxl) > NOTES_DXL_MAX_BYTES) {
            throw new RuntimeException('The Notes signature would be larger than ' . NOTES_DXL_MAX_BYTES . ' bytes.');
        }
        notesDxlSelfCheck($dxl);

        return [
            'dxl'             => $dxl,
            'complete'        => $this->complete,
            'images_embedded' => $this->embedded,
            'images_missing'  => $this->missing,
            'warnings'        => array_keys($this->warnings),
        ];
    }

    // -----------------------------------------------------------------
    // Parsing
    // -----------------------------------------------------------------

    private function parse(string $html): ?DOMElement
    {
        $html = mb_scrub($html, 'UTF-8');
        // Non-ASCII as numeric references: the HTML parser then needs no
        // encoding declaration and cannot guess wrong.
        $html = mb_encode_numericentity($html, [0x80, 0x10FFFF, 0, 0x1FFFFF], 'UTF-8');
        $doc = new DOMDocument();
        $previous = libxml_use_internal_errors(true);
        $ok = $doc->loadHTML(
            '<!DOCTYPE html><html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"></head><body>'
            . $html . '</body></html>',
            LIBXML_NONET | LIBXML_NOERROR | LIBXML_NOWARNING | LIBXML_COMPACT
        );
        libxml_clear_errors();
        libxml_use_internal_errors($previous);
        if (!$ok) {
            return null;
        }
        $body = $doc->getElementsByTagName('body')->item(0);
        return $body instanceof DOMElement ? $body : null;
    }

    private function rootContext(): array
    {
        return [
            'font'      => [
                'name' => NOTES_DXL_DEFAULT_FONT, 'size' => NOTES_DXL_DEFAULT_SIZE, 'bold' => false, 'italic' => false,
                'underline' => false, 'strike' => false, 'sup' => false, 'sub' => false, 'color' => null,
            ],
            'align'     => 'left',
            'indent'    => 0.0,
            'link'      => null,
            'pre'       => false,
            'transform' => '',
            'list'      => null,
            'li'        => null,
        ];
    }

    private function walkChildren(DOMNode $node, array $ctx, NotesDxlFlow $flow, int $depth): void
    {
        foreach ($node->childNodes as $child) {
            if ($child instanceof DOMText) {           // also covers CDATA sections
                $this->addText($flow, $child->nodeValue ?? '', $ctx);
            } elseif ($child instanceof DOMElement) {
                $this->walkElement($child, $ctx, $flow, $depth);
            }
        }
    }

    private function walkElement(DOMElement $el, array $ctx, NotesDxlFlow $flow, int $depth): void
    {
        $tag = strtolower($el->nodeName);
        if (isset(self::SKIP[$tag])) {
            if ($tag === 'style' && trim((string)$el->textContent) !== '') {
                $this->warn('CSS in <style> blocks is not applied in Notes; only inline styles are converted.');
            }
            return;
        }
        $style = $this->parseStyle($el->getAttribute('style'));
        if ($this->isHidden($el, $style)) {
            return;
        }
        $ctx = $this->applyStyle($ctx, $tag, $el, $style);

        switch ($tag) {
            case 'br':
                $this->addBreak($flow, $ctx);
                return;
            case 'img':
                $this->addImage($flow, $el, $style, $ctx);
                return;
            case 'hr':
                $this->addRule($flow, $el, $style, $ctx);
                return;
            case 'table':
                $this->addTable($flow, $el, $style, $ctx, $depth);
                return;
            case 'a':
                $href = $this->linkTarget($el->getAttribute('href'));
                if ($href !== null) {
                    $ctx['link'] = ['href' => $href, 'id' => ++$this->linkSeq];
                }
                $this->walkChildren($el, $ctx, $flow, $depth);
                return;
        }
        if (isset(self::BLOCKS[$tag])) {
            $this->addBlock($flow, $el, $tag, $style, $ctx, $depth);
            return;
        }
        $this->walkChildren($el, $ctx, $flow, $depth);
    }

    // -----------------------------------------------------------------
    // Styles
    // -----------------------------------------------------------------

    /**
     * @return array<string, string> property => value (lower-case property)
     */
    private function parseStyle(string $style): array
    {
        $out = [];
        foreach (explode(';', $style) as $decl) {
            $pos = strpos($decl, ':');
            if ($pos === false) {
                continue;
            }
            $prop = strtolower(trim(substr($decl, 0, $pos)));
            $value = trim((string)preg_replace('/!\s*important\s*$/i', '', substr($decl, $pos + 1)));
            if ($prop !== '' && $value !== '') {
                $out[$prop] = $value;
            }
        }
        return $out;
    }

    private function isHidden(DOMElement $el, array $style): bool
    {
        if ($el->hasAttribute('hidden')) {
            return true;
        }
        $display = strtolower($style['display'] ?? '');
        $visibility = strtolower($style['visibility'] ?? '');
        $msoHide = strtolower($style['mso-hide'] ?? '');
        return $display === 'none' || $visibility === 'hidden' || $msoHide === 'all';
    }

    /**
     * Applies an element's inherited text properties to the context.
     */
    private function applyStyle(array $ctx, string $tag, DOMElement $el, array $style): array
    {
        $f = $ctx['font'];
        $parentSize = $f['size'];
        switch ($tag) {
            case 'b': case 'strong': case 'th':
                $f['bold'] = true;
                break;
            case 'i': case 'em': case 'cite': case 'var': case 'dfn': case 'address':
                $f['italic'] = true;
                break;
            case 'u': case 'ins':
                $f['underline'] = true;
                break;
            case 's': case 'strike': case 'del':
                $f['strike'] = true;
                break;
            case 'sup':
                $f['sup'] = true;
                $f['sub'] = false;
                break;
            case 'sub':
                $f['sub'] = true;
                $f['sup'] = false;
                break;
            case 'small':
                $f['size'] = $parentSize * 0.83;
                break;
            case 'big':
                $f['size'] = $parentSize * 1.2;
                break;
            case 'code': case 'kbd': case 'samp': case 'tt': case 'pre':
                $f['name'] = 'Courier New';
                break;
            case 'h1': case 'h2': case 'h3': case 'h4': case 'h5': case 'h6':
                $f['size'] = $parentSize * self::HEADING_EM[$tag];
                $f['bold'] = true;
                break;
            case 'a':
                if ($el->hasAttribute('href')) {
                    // The usual link look; the element's own style may change it below.
                    $f['color'] = '#0000ee';
                    $f['underline'] = true;
                }
                break;
            case 'font':
                $face = $this->fontFamily($el->getAttribute('face'));
                if ($face !== null) {
                    $f['name'] = $face;
                }
                $size = $this->fontTagSize($el->getAttribute('size'));
                if ($size !== null) {
                    $f['size'] = $size;
                }
                $color = $this->color($el->getAttribute('color'));
                if ($color !== null && $color !== 'transparent') {
                    $f['color'] = $color;
                }
                break;
        }
        if ($tag === 'pre') {
            $ctx['pre'] = true;
        }

        if (isset($style['font'])) {
            $this->applyFontShorthand($f, $style['font'], $parentSize);
        }
        if (isset($style['font-family'])) {
            $name = $this->fontFamily($style['font-family']);
            if ($name !== null) {
                $f['name'] = $name;
            }
        }
        if (isset($style['font-size'])) {
            $size = $this->fontSize($style['font-size'], $parentSize);
            if ($size !== null) {
                $f['size'] = $size;
            }
        }
        if (isset($style['font-weight'])) {
            $w = strtolower($style['font-weight']);
            if ($w === 'bold' || $w === 'bolder' || (ctype_digit($w) && (int)$w >= 600)) {
                $f['bold'] = true;
            } elseif ($w === 'normal' || $w === 'lighter' || (ctype_digit($w) && (int)$w < 600)) {
                $f['bold'] = false;
            }
        }
        if (isset($style['font-style'])) {
            $s = strtolower($style['font-style']);
            if ($s === 'italic' || strpos($s, 'oblique') === 0) {
                $f['italic'] = true;
            } elseif ($s === 'normal') {
                $f['italic'] = false;
            }
        }
        foreach (['text-decoration', 'text-decoration-line'] as $prop) {
            if (isset($style[$prop])) {
                $d = strtolower($style[$prop]);
                if (strpos($d, 'none') !== false) {
                    $f['underline'] = false;
                    $f['strike'] = false;
                }
                if (strpos($d, 'underline') !== false) {
                    $f['underline'] = true;
                }
                if (strpos($d, 'line-through') !== false) {
                    $f['strike'] = true;
                }
            }
        }
        if (isset($style['color'])) {
            $color = $this->color($style['color']);
            if ($color !== null && $color !== 'transparent') {
                $f['color'] = $color;
            }
        }
        if (isset($style['vertical-align']) && !in_array($tag, ['td', 'th', 'tr', 'table', 'img'], true)) {
            $va = strtolower($style['vertical-align']);
            if ($va === 'super') {
                $f['sup'] = true;
                $f['sub'] = false;
            } elseif ($va === 'sub') {
                $f['sub'] = true;
                $f['sup'] = false;
            } elseif ($va === 'baseline') {
                $f['sup'] = false;
                $f['sub'] = false;
            }
        }
        if (isset($style['text-transform'])) {
            $t = strtolower($style['text-transform']);
            $ctx['transform'] = in_array($t, ['uppercase', 'lowercase'], true) ? $t : '';
        }
        if (isset(self::BLOCKS[$tag]) || $tag === 'table') {
            // align="..." on a table places the table; it does not align the text in it.
            $align = $this->alignment($style['text-align'] ?? ($tag === 'table' ? '' : $el->getAttribute('align')));
            if ($tag === 'center') {
                $align = 'center';
            }
            if ($align !== null) {
                $ctx['align'] = $align;
            }
        }
        $ctx['font'] = $f;
        return $ctx;
    }

    private function applyFontShorthand(array &$f, string $value, float $parentSize): void
    {
        // e.g. "bold 13px/1.4 Arial, sans-serif" or "italic 10pt Verdana"
        if (!preg_match('/^(.*?)(\d+(?:\.\d+)?(?:px|pt|em|rem|%)|xx-small|x-small|small|medium|large|x-large|xx-large|smaller|larger)(?:\s*\/\s*\S+)?\s+(.+)$/i', trim($value), $m)) {
            return;
        }
        $pre = strtolower($m[1]);
        if (preg_match('/\b(bold|bolder|[6-9]00)\b/', $pre)) {
            $f['bold'] = true;
        }
        if (preg_match('/\b(italic|oblique)\b/', $pre)) {
            $f['italic'] = true;
        }
        $size = $this->fontSize($m[2], $parentSize);
        if ($size !== null) {
            $f['size'] = $size;
        }
        $name = $this->fontFamily($m[3]);
        if ($name !== null) {
            $f['name'] = $name;
        }
    }

    /**
     * First usable font name of a CSS font-family list; generic families map to
     * common Windows fonts. Null when nothing usable is given.
     */
    private function fontFamily(string $value): ?string
    {
        foreach (explode(',', $value) as $name) {
            $name = trim($name, " \t\n\r\"'");
            $lower = strtolower($name);
            if ($lower === '' || $lower === 'inherit' || $lower === 'initial' || $lower === 'unset') {
                continue;
            }
            $generic = [
                'sans-serif' => 'Arial', 'serif' => 'Times New Roman', 'monospace' => 'Courier New',
                'system-ui' => 'Segoe UI', '-apple-system' => 'Segoe UI', 'cursive' => 'Comic Sans MS',
                'fantasy' => 'Impact',
            ];
            if (isset($generic[$lower])) {
                return $generic[$lower];
            }
            if (preg_match('/^[\p{L}\p{N}][\p{L}\p{N} ._\-]{0,47}$/u', $name)) {
                return $name;
            }
        }
        return null;
    }

    /** Font size in points, or null when the value cannot be used. */
    private function fontSize(string $value, float $parentPt): ?float
    {
        $v = strtolower(trim($value));
        $keywords = [
            'xx-small' => 7.0, 'x-small' => 7.5, 'small' => 10.0, 'medium' => 12.0, 'large' => 13.5,
            'x-large' => 18.0, 'xx-large' => 24.0, 'xxx-large' => 36.0,
        ];
        if (isset($keywords[$v])) {
            return $keywords[$v];
        }
        if ($v === 'smaller') {
            return $parentPt * 0.83;
        }
        if ($v === 'larger') {
            return $parentPt * 1.2;
        }
        if (!preg_match('/^(\d+(?:\.\d+)?|\.\d+)(px|pt|em|rem|%)?$/', $v, $m)) {
            return null;
        }
        $n = (float)$m[1];
        switch ($m[2] ?? '') {
            case 'pt':
                $pt = $n;
                break;
            case 'em':
                $pt = $parentPt * $n;
                break;
            case 'rem':
                $pt = 12.0 * $n;
                break;
            case '%':
                $pt = $parentPt * $n / 100;
                break;
            default:                                    // px, or a bare number
                $pt = $n * 0.75;
        }
        return min($pt, 72.0);
    }

    /** <font size="1".."7" / "+1" / "-1"> in points. */
    private function fontTagSize(string $value): ?float
    {
        $v = trim($value);
        if (!preg_match('/^([+-]?)([1-7])$/', $v, $m)) {
            return null;
        }
        $n = (int)$m[2];
        if ($m[1] === '+') {
            $n = min(7, 3 + $n);
        } elseif ($m[1] === '-') {
            $n = max(1, 3 - $n);
        }
        return [1 => 7.5, 2 => 10.0, 3 => 12.0, 4 => 13.5, 5 => 18.0, 6 => 24.0, 7 => 36.0][$n];
    }

    /**
     * Normalises a CSS/HTML colour to "#rrggbb", "transparent" or null.
     */
    private function color(string $value): ?string
    {
        $v = strtolower(trim($value));
        if ($v === '') {
            return null;
        }
        if ($v === 'transparent') {
            return 'transparent';
        }
        if (isset(self::NAMED_COLORS[$v])) {
            return self::NAMED_COLORS[$v];
        }
        if (preg_match('/^#?([0-9a-f]{3})$/', $v, $m)) {
            $h = $m[1];
            return '#' . $h[0] . $h[0] . $h[1] . $h[1] . $h[2] . $h[2];
        }
        if (preg_match('/^#?([0-9a-f]{6})(?:[0-9a-f]{2})?$/', $v, $m)) {
            return '#' . $m[1];
        }
        if (preg_match('/^rgba?\(\s*(\d{1,3})\s*[, ]\s*(\d{1,3})\s*[, ]\s*(\d{1,3})\s*(?:[,\/]\s*([\d.]+%?)\s*)?\)$/', $v, $m)) {
            if (isset($m[4]) && $m[4] !== '' && (float)$m[4] === 0.0) {
                return 'transparent';
            }
            return sprintf('#%02x%02x%02x', min(255, (int)$m[1]), min(255, (int)$m[2]), min(255, (int)$m[3]));
        }
        return null;
    }

    private function alignment(string $value): ?string
    {
        $v = strtolower(trim($value));
        $map = ['left' => 'left', 'start' => 'left', 'center' => 'center', 'middle' => 'center',
                'right' => 'right', 'end' => 'right', 'justify' => 'full'];
        return $map[$v] ?? null;
    }

    /**
     * A length in pixels (px, pt, em, rem, or a bare number as in HTML
     * attributes). Percentages and "auto" give null.
     */
    private function px(string $value, float $fontPt): ?float
    {
        $v = strtolower(trim($value));
        if (!preg_match('/^(-?\d+(?:\.\d+)?|-?\.\d+)(px|pt|em|rem)?$/', $v, $m)) {
            return null;
        }
        $n = (float)$m[1];
        switch ($m[2] ?? '') {
            case 'pt':
                return $n * 96 / 72;
            case 'em':
                return $n * $fontPt * 96 / 72;
            case 'rem':
                return $n * 16;
            default:
                return $n;
        }
    }

    /**
     * Box values (margin/padding shorthand plus the single sides) in pixels:
     * [top, right, bottom, left].
     */
    private function box(array $style, string $prop, float $fontPt, array $default): array
    {
        $box = $default;
        if (isset($style[$prop])) {
            $parts = preg_split('/\s+/', trim($style[$prop])) ?: [];
            $vals = [];
            foreach ($parts as $p) {
                $vals[] = $this->px($p, $fontPt);
            }
            $n = count($vals);
            if ($n >= 1 && $n <= 4) {
                $map = [1 => [0, 0, 0, 0], 2 => [0, 1, 0, 1], 3 => [0, 1, 2, 1], 4 => [0, 1, 2, 3]][$n];
                foreach ($map as $side => $idx) {
                    if ($vals[$idx] !== null) {
                        $box[$side] = $vals[$idx];
                    }
                }
            }
        }
        foreach (['top', 'right', 'bottom', 'left'] as $side => $name) {
            if (isset($style[$prop . '-' . $name])) {
                $v = $this->px($style[$prop . '-' . $name], $fontPt);
                if ($v !== null) {
                    $box[$side] = $v;
                }
            }
        }
        return $box;
    }

    // -----------------------------------------------------------------
    // Text, breaks, pictures, rules
    // -----------------------------------------------------------------

    private function ensurePar(NotesDxlFlow $flow, array $ctx): void
    {
        if ($flow->par !== null) {
            return;
        }
        $list = 'none';
        if ($ctx['li'] !== null && !isset($this->listUsed[$ctx['li']['id']])) {
            $this->listUsed[$ctx['li']['id']] = true;
            $list = $ctx['li']['type'];
        }
        $flow->par = [
            'type'   => 'par',
            'align'  => $ctx['align'],
            'indent' => $ctx['indent'],
            'list'   => $list,
            'before' => $flow->pendingBefore,
            'after'  => '1',
            'items'  => [],
        ];
        $flow->pendingBefore = '1';
    }

    private function closePar(NotesDxlFlow $flow): void
    {
        $par = $flow->par;
        $flow->par = null;
        if ($par === null) {
            return;
        }
        $this->trimTrailingSpace($par['items']);
        $n = count($par['items']);
        // A line break at the end of a block does not add a line (as in HTML) -
        // unless it is the only content: then it is one empty line.
        if ($n > 1 && $par['items'][$n - 1]['k'] === 'br') {
            array_pop($par['items']);
            $this->trimTrailingSpace($par['items']);
        }
        if (!$par['items']) {
            return;
        }
        $flow->blocks[] = $par;
    }

    /** Removes spaces at the end of the item list (also inside a final link). */
    private function trimTrailingSpace(array &$items): void
    {
        while ($items) {
            $last = count($items) - 1;
            $item = &$items[$last];
            if ($item['k'] === 'text') {
                $item['text'] = rtrim($item['text'], ' ');
                if ($item['text'] === '') {
                    unset($item);
                    array_pop($items);
                    continue;
                }
            } elseif ($item['k'] === 'link') {
                $this->trimTrailingSpace($item['items']);
                if (!$item['items']) {
                    unset($item);
                    array_pop($items);
                    continue;
                }
            }
            unset($item);
            return;
        }
    }

    /** True when the paragraph is empty or ends with a space or a break. */
    private function atLineStart(?array $par): bool
    {
        if ($par === null || !$par['items']) {
            return true;
        }
        $last = $par['items'][count($par['items']) - 1];
        if ($last['k'] === 'link') {
            if (!$last['items']) {
                return true;
            }
            $last = $last['items'][count($last['items']) - 1];
        }
        if ($last['k'] === 'br') {
            return true;
        }
        return $last['k'] === 'text' && substr($last['text'], -1) === ' ';
    }

    /**
     * Appends an inline item to the open paragraph; inside a link it goes into
     * the link (a new one when the previous item is not the same link).
     */
    private function appendInline(NotesDxlFlow $flow, array $item, array $ctx): void
    {
        $this->ensurePar($flow, $ctx);
        $items = &$flow->par['items'];
        if ($ctx['link'] !== null && $item['k'] !== 'br') {
            $n = count($items);
            if ($n === 0 || $items[$n - 1]['k'] !== 'link' || $items[$n - 1]['id'] !== $ctx['link']['id']) {
                $items[] = ['k' => 'link', 'href' => $ctx['link']['href'], 'id' => $ctx['link']['id'], 'items' => []];
                $n++;
            }
            $this->pushItem($items[$n - 1]['items'], $item);
        } else {
            $this->pushItem($items, $item);
        }
        unset($items);
    }

    private function pushItem(array &$items, array $item): void
    {
        $n = count($items);
        if ($item['k'] === 'text' && $n > 0 && $items[$n - 1]['k'] === 'text' && $items[$n - 1]['f'] === $item['f']) {
            $items[$n - 1]['text'] .= $item['text'];
            return;
        }
        $items[] = $item;
    }

    private function addText(NotesDxlFlow $flow, string $text, array $ctx): void
    {
        if ($ctx['font']['size'] < 0.5) {
            return;                                     // font-size:0 text is invisible
        }
        if ($ctx['transform'] === 'uppercase') {
            $text = mb_strtoupper($text, 'UTF-8');
        } elseif ($ctx['transform'] === 'lowercase') {
            $text = mb_strtolower($text, 'UTF-8');
        }
        if ($ctx['pre']) {
            $lines = preg_split('/\r\n|\r|\n/', str_replace("\t", '    ', $text)) ?: [];
            foreach ($lines as $i => $line) {
                if ($i > 0) {
                    $this->addBreak($flow, $ctx);
                }
                if ($line !== '') {
                    $this->appendInline($flow, ['k' => 'text', 'text' => $line, 'f' => $ctx['font']], $ctx);
                }
            }
            return;
        }
        $text = (string)preg_replace('/[ \t\n\r\f]+/', ' ', $text);
        if (preg_match('/[\x{1F000}-\x{1FAFF}\x{2600}-\x{27BF}]/u', $text)) {
            $this->warn('The signature contains emoji or symbol characters; Notes shows them only if the font has them.');
        }
        if ($this->atLineStart($flow->par)) {
            $text = ltrim($text, ' ');
        }
        if ($text === '') {
            return;
        }
        $this->appendInline($flow, ['k' => 'text', 'text' => $text, 'f' => $ctx['font']], $ctx);
    }

    private function addBreak(NotesDxlFlow $flow, array $ctx): void
    {
        $this->ensurePar($flow, $ctx);
        $this->trimTrailingSpace($flow->par['items']);
        $flow->par['items'][] = ['k' => 'br', 'f' => $ctx['font']];
    }

    private function addRule(NotesDxlFlow $flow, DOMElement $el, array $style, array $ctx): void
    {
        $this->closePar($flow);
        $color = null;
        foreach (['border-top-color', 'border-color', 'background-color', 'color'] as $prop) {
            if ($color === null && isset($style[$prop])) {
                $c = $this->color($style[$prop]);
                $color = ($c !== null && $c !== 'transparent') ? $c : null;
            }
        }
        if ($color === null && isset($style['border-top'])) {
            $color = $this->borderSide($style['border-top'])['color'];
        }
        if ($color === null && isset($style['border'])) {
            $color = $this->borderSide($style['border'])['color'];
        }
        if ($color === null) {
            $c = $this->color($el->getAttribute('color'));
            $color = ($c !== null && $c !== 'transparent') ? $c : '#d0d0d0';
        }
        $height = $this->px($style['height'] ?? '', $ctx['font']['size']);
        if ($height === null && isset($style['border-top'])) {
            $top = $this->borderSide($style['border-top'])['width'];
            $height = $top > 0 ? $top : null;
        }
        $height = $height ?? $this->px($el->getAttribute('size'), $ctx['font']['size']) ?? 1.0;
        $width = '100%';
        $w = trim($style['width'] ?? $el->getAttribute('width'));
        if (preg_match('/^(\d{1,3})%$/', $w, $m) && (int)$m[1] > 0 && (int)$m[1] <= 100) {
            $width = (int)$m[1] . '%';
        } elseif (($px = $this->px($w, $ctx['font']['size'])) !== null && $px > 0) {
            $width = $this->inches(min($px, NOTES_DXL_MAX_TABLE_WIDTH));
        }
        $this->ensurePar($flow, $ctx);
        $flow->par['items'][] = ['k' => 'hr', 'color' => $color, 'height' => max(1.0, min($height, 20.0)), 'width' => $width];
        $this->closePar($flow);
    }

    private function addImage(NotesDxlFlow $flow, DOMElement $el, array $style, array $ctx): void
    {
        $src = trim($el->getAttribute('src'));
        if ($src === '') {
            return;
        }
        $alt = trim((string)preg_replace('/\s+/', ' ', $el->getAttribute('alt')));
        $res = ($this->resolveImage)($src);
        $status = (string)($res['status'] ?? 'not_found');
        $bytes = ($status === 'ok') ? (string)($res['bytes'] ?? '') : '';
        if ($status === 'ok' && $this->imageBytes + strlen($bytes) > NOTES_DXL_MAX_IMAGE_BYTES_TOTAL) {
            $status = 'too_large_total';
        }
        $format = ['image/png' => 'png', 'image/gif' => 'gif', 'image/jpeg' => 'jpeg'][(string)($res['content_type'] ?? '')] ?? '';
        $size = ($status === 'ok') ? @getimagesizefromstring($bytes) : false;
        if ($status === 'ok' && ($format === '' || !is_array($size) || $size[0] < 1 || $size[1] < 1)) {
            $status = 'unsupported_type';
        }
        if ($status !== 'ok') {
            $this->missing[] = ['src' => substr((string)($res['url'] ?? $src), 0, 300), 'status' => $status];
            if (isset(self::TEMPORARY_IMAGE_STATUS[$status])) {
                $this->complete = false;
            }
            $this->warn('Not every picture could be embedded (see images_missing).');
            if ($alt !== '') {
                $this->addText($flow, $alt, $ctx);    // like a mail client that shows the alt text
            }
            return;
        }

        [$w, $h] = $this->imageSize($el, $style, (int)$size[0], (int)$size[1], $ctx['font']['size']);
        if ($w <= 1 && $h <= 1) {
            return;                                     // tracking pixel or spacer
        }
        $this->imageBytes += strlen($bytes);
        $this->embedded++;
        $this->appendInline($flow, [
            'k' => 'img', 'format' => $format, 'data' => base64_encode($bytes), 'w' => $w, 'h' => $h,
            'alt' => mb_substr($alt, 0, 200, 'UTF-8'),
        ], $ctx);
    }

    /** Display size of a picture: HTML attributes, CSS, max-width/height, proportions. */
    private function imageSize(DOMElement $el, array $style, int $iw, int $ih, float $fontPt): array
    {
        $w = $this->px($style['width'] ?? '', $fontPt) ?? $this->px($el->getAttribute('width'), $fontPt);
        $h = $this->px($style['height'] ?? '', $fontPt) ?? $this->px($el->getAttribute('height'), $fontPt);
        if ($w !== null && $w <= 0) {
            $w = null;
        }
        if ($h !== null && $h <= 0) {
            $h = null;
        }
        if ($w === null && $h === null) {
            $w = $iw;
            $h = $ih;
        } elseif ($w === null) {
            $w = $h * $iw / $ih;
        } elseif ($h === null) {
            $h = $w * $ih / $iw;
        }
        $maxW = $this->px($style['max-width'] ?? '', $fontPt);
        if ($maxW !== null && $maxW > 0 && $w > $maxW) {
            $h = $h * $maxW / $w;
            $w = $maxW;
        }
        $maxH = $this->px($style['max-height'] ?? '', $fontPt);
        if ($maxH !== null && $maxH > 0 && $h > $maxH) {
            $w = $w * $maxH / $h;
            $h = $maxH;
        }
        return [max(1, min(2000, (int)round($w))), max(1, min(2000, (int)round($h)))];
    }

    /**
     * Link target if it is http(s), mailto or tel; anything else is not linked.
     */
    private function linkTarget(string $href): ?string
    {
        $href = trim($href);
        if ($href === '' || strlen($href) > 2000 || preg_match('/[\x00-\x20\x7f"\'<>\\\\]/', $href)) {
            return null;
        }
        if (preg_match('#^https?://[^/?\#]+#i', $href) || preg_match('/^mailto:[^\s]+$/i', $href)) {
            return $href;
        }
        if (preg_match('/^tel:[0-9+().\-\/]+$/i', $href)) {
            return $href;
        }
        return null;
    }

    // -----------------------------------------------------------------
    // Blocks and lists
    // -----------------------------------------------------------------

    private function addBlock(NotesDxlFlow $flow, DOMElement $el, string $tag, array $style, array $ctx, int $depth): void
    {
        $this->closePar($flow);
        $fontPt = $ctx['font']['size'];
        $em = $fontPt * 96 / 72;
        $defaults = [0.0, 0.0, 0.0, 0.0];
        if (in_array($tag, ['p', 'blockquote', 'dl', 'figure'], true)) {
            $defaults = [$em, 0.0, $em, 0.0];
        } elseif (isset(self::HEADING_EM[$tag])) {
            $hm = ['h1' => 0.67, 'h2' => 0.83, 'h3' => 1.0, 'h4' => 1.33, 'h5' => 1.67, 'h6' => 2.33][$tag] * $em;
            $defaults = [$hm, 0.0, $hm, 0.0];
        } elseif (($tag === 'ul' || $tag === 'ol') && $ctx['list'] === null) {
            $defaults = [$em, 0.0, $em, 0.0];
        }
        $margin = $this->box($style, 'margin', $fontPt, $defaults);
        $padding = $this->box($style, 'padding', $fontPt, [0.0, 0.0, 0.0, 0.0]);

        $indent = max(0.0, $margin[3]) + max(0.0, $padding[3]);
        if ($tag === 'blockquote' && !isset($style['margin']) && !isset($style['margin-left'])) {
            $indent += 40;
        }
        if ($tag === 'dd') {
            $indent += 40;
        }
        if ($tag === 'ul' || $tag === 'ol') {
            $level = $ctx['list'] === null ? 1 : $ctx['list']['level'] + 1;
            $ctx['list'] = ['type' => $tag === 'ol' ? 'number' : 'bullet', 'level' => $level];
            $indent += 24;
        }
        if ($tag === 'li') {
            // Only the first paragraph of the item gets the bullet or number.
            $type = $ctx['list']['type'] ?? 'bullet';
            $ctx['li'] = ['id' => ++$this->listSeq, 'type' => $type];
        }
        $ctx['indent'] += $indent;

        $this->requestSpace($flow, $margin[0] + $padding[0], $fontPt, true);
        $start = count($flow->blocks);
        $this->walkChildren($el, $ctx, $flow, $depth);
        $this->closePar($flow);
        if (count($flow->blocks) > $start) {
            $this->requestSpace($flow, $margin[2] + $padding[2], $fontPt, false);
        } else {
            $flow->pendingBefore = '1';
        }
    }

    /**
     * Turns a vertical margin into Notes paragraph spacing ("1", "1.5" or "2" lines).
     */
    private function spacing(float $px, float $fontPt): string
    {
        $line = max(1.0, $fontPt * 96 / 72 * 1.2);
        $r = $px / $line;
        return $r >= 0.75 ? '2' : ($r >= 0.25 ? '1.5' : '1');
    }

    private function requestSpace(NotesDxlFlow $flow, float $px, float $fontPt, bool $before): void
    {
        $s = $this->spacing($px, $fontPt);
        if ($s === '1') {
            return;
        }
        if ($before) {
            // Adjacent margins collapse: no extra space if the previous paragraph has it already.
            $n = count($flow->blocks);
            if ($n > 0 && $flow->blocks[$n - 1]['type'] === 'par' && (float)$flow->blocks[$n - 1]['after'] >= (float)$s) {
                return;
            }
            if ((float)$s > (float)$flow->pendingBefore) {
                $flow->pendingBefore = $s;
            }
            return;
        }
        $n = count($flow->blocks);
        if ($n > 0 && $flow->blocks[$n - 1]['type'] === 'par' && (float)$s > (float)$flow->blocks[$n - 1]['after']) {
            $flow->blocks[$n - 1]['after'] = $s;
        }
    }

    // -----------------------------------------------------------------
    // Tables
    // -----------------------------------------------------------------

    /**
     * Border of one side from a CSS border shorthand: width (px), visible, colour.
     *
     * @return array{width: float, color: ?string}
     */
    private function borderSide(string $value): array
    {
        $width = null;
        $styleVal = null;
        $color = null;
        foreach (preg_split('/\s+(?![^(]*\))/', trim($value)) ?: [] as $tok) {
            $t = strtolower($tok);
            if (in_array($t, ['none', 'hidden', 'solid', 'dashed', 'dotted', 'double', 'groove', 'ridge', 'inset', 'outset'], true)) {
                $styleVal = $t;
            } elseif (in_array($t, ['thin', 'medium', 'thick'], true)) {
                $width = ['thin' => 1.0, 'medium' => 3.0, 'thick' => 5.0][$t];
            } elseif (($px = $this->px($t, NOTES_DXL_DEFAULT_SIZE)) !== null) {
                $width = $px;
            } elseif (($c = $this->color($tok)) !== null) {
                $color = $c === 'transparent' ? null : $c;
            }
        }
        if ($styleVal === null || $styleVal === 'none' || $styleVal === 'hidden') {
            return ['width' => 0.0, 'color' => $color];
        }
        return ['width' => $width ?? 3.0, 'color' => $color];
    }

    /**
     * Cell borders [top, right, bottom, left] in pixels and the first colour.
     *
     * @return array{0: float[], 1: ?string}
     */
    private function cellBorders(array $style, bool $tableBorder): array
    {
        $sides = ['top', 'right', 'bottom', 'left'];
        $w = $tableBorder ? [1.0, 1.0, 1.0, 1.0] : [0.0, 0.0, 0.0, 0.0];
        $styles = $tableBorder ? array_fill(0, 4, 'solid') : array_fill(0, 4, null);
        $colors = $tableBorder ? array_fill(0, 4, '#808080') : array_fill(0, 4, null);
        $widthSet = $tableBorder ? array_fill(0, 4, true) : array_fill(0, 4, false);

        $apply = function (int $i, string $value) use (&$w, &$styles, &$colors, &$widthSet): void {
            $b = $this->borderSide($value);
            $w[$i] = $b['width'];
            $styles[$i] = $b['width'] > 0 ? 'solid' : 'none';
            $widthSet[$i] = true;
            if ($b['color'] !== null) {
                $colors[$i] = $b['color'];
            }
        };
        if (isset($style['border'])) {
            for ($i = 0; $i < 4; $i++) {
                $apply($i, $style['border']);
            }
        }
        foreach ($sides as $i => $side) {
            if (isset($style['border-' . $side])) {
                $apply($i, $style['border-' . $side]);
            }
        }
        // Longhand properties.
        foreach (['width', 'style', 'color'] as $part) {
            if (isset($style['border-' . $part])) {
                $vals = preg_split('/\s+(?![^(]*\))/', trim($style['border-' . $part])) ?: [];
                $n = count($vals);
                $map = [1 => [0, 0, 0, 0], 2 => [0, 1, 0, 1], 3 => [0, 1, 2, 1], 4 => [0, 1, 2, 3]][$n] ?? null;
                if ($map !== null) {
                    foreach ($map as $i => $idx) {
                        $this->borderPart($part, $vals[$idx], $i, $w, $styles, $colors, $widthSet);
                    }
                }
            }
            foreach ($sides as $i => $side) {
                if (isset($style['border-' . $side . '-' . $part])) {
                    $this->borderPart($part, $style['border-' . $side . '-' . $part], $i, $w, $styles, $colors, $widthSet);
                }
            }
        }
        $out = [];
        $color = null;
        for ($i = 0; $i < 4; $i++) {
            $visible = $styles[$i] !== null && $styles[$i] !== 'none' && $styles[$i] !== 'hidden';
            $width = $visible ? ($widthSet[$i] ? $w[$i] : 3.0) : 0.0;
            $out[$i] = max(0.0, min(10.0, round($width)));
            if ($out[$i] > 0 && $color === null) {
                $color = $colors[$i] ?? '#000000';
            }
        }
        return [$out, $color];
    }

    private function borderPart(string $part, string $value, int $i, array &$w, array &$styles, array &$colors, array &$widthSet): void
    {
        $v = strtolower(trim($value));
        if ($part === 'width') {
            $px = ['thin' => 1.0, 'medium' => 3.0, 'thick' => 5.0][$v] ?? $this->px($v, NOTES_DXL_DEFAULT_SIZE);
            if ($px !== null) {
                $w[$i] = $px;
                $widthSet[$i] = true;
            }
        } elseif ($part === 'style') {
            $styles[$i] = $v;
        } else {
            $c = $this->color($v);
            if ($c !== null && $c !== 'transparent') {
                $colors[$i] = $c;
            }
        }
    }

    private function background(DOMElement $el, array $style): ?string
    {
        foreach ([$style['background-color'] ?? '', $el->getAttribute('bgcolor')] as $v) {
            $c = $this->color($v);
            if ($c !== null) {
                return $c === 'transparent' ? null : $c;
            }
        }
        if (isset($style['background'])) {
            foreach (preg_split('/\s+(?![^(]*\))/', trim($style['background'])) ?: [] as $tok) {
                $c = $this->color($tok);
                if ($c !== null) {
                    return $c === 'transparent' ? null : $c;
                }
            }
        }
        return null;
    }

    /** @return DOMElement[] the rows of a table (also inside thead/tbody/tfoot) */
    private function tableRows(DOMElement $table): array
    {
        $rows = [];
        foreach ($table->childNodes as $child) {
            if (!$child instanceof DOMElement) {
                continue;
            }
            $name = strtolower($child->nodeName);
            if ($name === 'tr') {
                $rows[] = $child;
            } elseif ($name === 'thead' || $name === 'tbody' || $name === 'tfoot') {
                foreach ($child->childNodes as $tr) {
                    if ($tr instanceof DOMElement && strtolower($tr->nodeName) === 'tr') {
                        $rows[] = $tr;
                    }
                }
            }
        }
        return $rows;
    }

    private function addTable(NotesDxlFlow $flow, DOMElement $table, array $style, array $ctx, int $depth): void
    {
        $this->closePar($flow);
        $fontPt = $ctx['font']['size'];

        // A caption comes before the table.
        foreach ($table->childNodes as $child) {
            if ($child instanceof DOMElement && strtolower($child->nodeName) === 'caption') {
                $this->walkElement($child, $ctx, $flow, $depth);
            }
        }

        $tableBorder = (int)$table->getAttribute('border') > 0;
        $cellPadding = $table->hasAttribute('cellpadding') ? max(0.0, (float)$this->px($table->getAttribute('cellpadding'), $fontPt)) : 1.0;
        $tableBg = $this->background($table, $style);
        $tableWidth = $this->px($style['width'] ?? '', $fontPt) ?? $this->px($table->getAttribute('width'), $fontPt);

        // Place the cells on a grid (row and column spans).
        $grid = [];
        $cells = [];
        $ncols = 0;
        $r = 0;
        foreach ($this->tableRows($table) as $tr) {
            $trStyle = $this->parseStyle($tr->getAttribute('style'));
            if ($this->isHidden($tr, $trStyle)) {
                continue;
            }
            $rowCtx = $this->applyStyle($ctx, 'tr', $tr, $trStyle);
            $rowBg = $this->background($tr, $trStyle);
            $rowValign = $this->valign($trStyle['vertical-align'] ?? $tr->getAttribute('valign'));
            $c = 0;
            foreach ($tr->childNodes as $td) {
                if (!$td instanceof DOMElement) {
                    continue;
                }
                $name = strtolower($td->nodeName);
                if ($name !== 'td' && $name !== 'th') {
                    continue;
                }
                while (isset($grid[$r][$c])) {
                    $c++;
                }
                $cs = max(1, min(20, (int)($td->getAttribute('colspan') ?: 1)));
                $rs = max(1, min(20, (int)($td->getAttribute('rowspan') ?: 1)));
                $idx = count($cells);
                $cells[] = $this->buildCell($td, $name, $rowCtx, $rowBg, $rowValign, $tableBorder, $cellPadding, $depth)
                         + ['r' => $r, 'c' => $c, 'cs' => $cs, 'rs' => $rs];
                for ($i = 0; $i < $rs; $i++) {
                    for ($j = 0; $j < $cs; $j++) {
                        $grid[$r + $i][$c + $j] = $idx;
                    }
                }
                $c += $cs;
                $ncols = max($ncols, $c);
            }
            $r++;
        }
        $nrows = $r;
        if ($nrows === 0 || $ncols === 0) {
            return;
        }
        // Row spans end with the table (as in HTML).
        foreach (array_keys($grid) as $row) {
            if ($row >= $nrows) {
                unset($grid[$row]);
            }
        }
        foreach ($cells as $i => $cell) {
            $cells[$i]['rs'] = min($cell['rs'], $nrows - $cell['r']);
        }

        $visible = $tableBg !== null;
        foreach ($cells as $cell) {
            if ($cell['bg'] !== null || max($cell['borders']) > 0) {
                $visible = true;
            }
        }

        // Too deep, or a layout table with one column and nothing to see:
        // the cells' content goes straight into the surrounding flow.
        if ($depth >= NOTES_DXL_MAX_TABLE_DEPTH || ($ncols === 1 && !$visible)) {
            if ($depth >= NOTES_DXL_MAX_TABLE_DEPTH) {
                $this->warn('Tables nested deeper than ' . NOTES_DXL_MAX_TABLE_DEPTH . ' levels were flattened.');
            }
            usort($cells, function (array $a, array $b): int {
                return [$a['r'], $a['c']] <=> [$b['r'], $b['c']];
            });
            foreach ($cells as $cell) {
                $this->appendBlocks($flow, $cell['blocks'], $ctx['indent'] + $cell['pad'][3]);
            }
            return;
        }

        // Rows that consist of one plain cell over all columns at the start or
        // end of the table become paragraphs before / after the table.
        $isPlainFullRow = function (int $row) use ($grid, $cells, $ncols): bool {
            $idx = $grid[$row][0] ?? null;
            if ($idx === null) {
                return false;
            }
            $cell = $cells[$idx];
            return $cell['r'] === $row && $cell['rs'] === 1 && $cell['cs'] >= $ncols
                && $cell['bg'] === null && max($cell['borders']) == 0;
        };
        $first = 0;
        $last = $nrows - 1;
        if ($ncols > 1) {
            while ($first <= $last && $isPlainFullRow($first)) {
                $first++;
            }
            while ($last >= $first && $isPlainFullRow($last)) {
                $last--;
            }
        }
        for ($row = 0; $row < $first; $row++) {
            $cell = $cells[$grid[$row][0]];
            $this->appendBlocks($flow, $cell['blocks'], $ctx['indent'] + $cell['pad'][3]);
        }
        if ($first <= $last) {
            $flow->blocks[] = $this->tableBlock($cells, $grid, $first, $last, $ncols, $tableBg, $tableWidth, $table, $style, $ctx);
        }
        for ($row = $last + 1; $row < $nrows; $row++) {
            if (!isset($grid[$row][0])) {
                continue;
            }
            $cell = $cells[$grid[$row][0]];
            $this->appendBlocks($flow, $cell['blocks'], $ctx['indent'] + $cell['pad'][3]);
        }
    }

    private function valign(string $value): ?string
    {
        $v = strtolower(trim($value));
        return ['top' => 'top', 'middle' => 'center', 'center' => 'center', 'bottom' => 'bottom'][$v] ?? null;
    }

    /** Converts one table cell into its own flow plus the cell properties. */
    private function buildCell(DOMElement $td, string $name, array $ctx, ?string $rowBg, ?string $rowValign,
                               bool $tableBorder, float $cellPadding, int $depth): array
    {
        $style = $this->parseStyle($td->getAttribute('style'));
        $cflow = new NotesDxlFlow();
        $pad = [$cellPadding, $cellPadding, $cellPadding, $cellPadding];
        $borders = [0.0, 0.0, 0.0, 0.0];
        $color = null;
        $bg = $rowBg;
        $valign = $rowValign ?? 'center';
        $width = null;

        if (!$this->isHidden($td, $style)) {
            $cctx = $this->applyStyle($ctx, $name, $td, $style);
            if ($name === 'th' && $this->alignment($style['text-align'] ?? $td->getAttribute('align')) === null) {
                $cctx['align'] = 'center';
            }
            $cctx['indent'] = 0.0;
            $cctx['list'] = null;
            $cctx['li'] = null;
            $cctx['link'] = null;
            $fontPt = $cctx['font']['size'];
            $pad = $this->box($style, 'padding', $fontPt, $pad);
            [$borders, $color] = $this->cellBorders($style, $tableBorder);
            $bg = $this->background($td, $style) ?? $rowBg;
            $valign = $this->valign($style['vertical-align'] ?? $td->getAttribute('valign')) ?? $valign;
            $width = $this->px($style['width'] ?? '', $fontPt) ?? $this->px($td->getAttribute('width'), $fontPt);

            if ($pad[0] >= 4) {
                $cflow->blocks[] = $this->spacer($pad[0]);
            }
            $this->walkChildren($td, $cctx, $cflow, $depth + 1);
            $this->closePar($cflow);
            if ($pad[2] >= 4) {
                $cflow->blocks[] = $this->spacer($pad[2]);
            }
        }
        $pad = array_map(function ($v) {
            return max(0.0, (float)$v);
        }, $pad);
        return ['blocks' => $cflow->blocks, 'pad' => $pad, 'borders' => $borders, 'color' => $color,
                'bg' => $bg, 'valign' => $valign, 'width' => ($width !== null && $width > 0) ? $width : null];
    }

    /** An empty paragraph whose font size makes a gap of about $px pixels. */
    private function spacer(float $px): array
    {
        $pt = max(1, min(48, (int)round($px * 0.75 / 1.2)));
        return ['type' => 'spacer', 'size' => $pt, 'indent' => 0.0];
    }

    /** Appends blocks of another flow, shifted by $indent pixels. */
    private function appendBlocks(NotesDxlFlow $flow, array $blocks, float $indent): void
    {
        $this->closePar($flow);
        foreach ($blocks as $block) {
            $block['indent'] = ($block['indent'] ?? 0.0) + $indent;
            if ($block['type'] === 'par') {
                if ($flow->pendingBefore !== '1' && (float)$flow->pendingBefore > (float)$block['before']) {
                    $block['before'] = $flow->pendingBefore;
                }
                // Adjacent margins collapse, as within one container.
                $n = count($flow->blocks);
                if ($n > 0 && $flow->blocks[$n - 1]['type'] === 'par'
                    && (float)$flow->blocks[$n - 1]['after'] >= (float)$block['before']) {
                    $block['before'] = '1';
                }
            }
            $flow->pendingBefore = '1';
            $flow->blocks[] = $block;
        }
    }

    private function tableBlock(array $cells, array $grid, int $first, int $last, int $ncols, ?string $tableBg,
                                ?float $tableWidth, DOMElement $table, array $style, array $ctx): array
    {
        // Border colour: Notes has one per table.
        $color = null;
        foreach ($cells as $cell) {
            if ($cell['r'] < $first || $cell['r'] > $last || $cell['color'] === null) {
                continue;
            }
            if ($color === null) {
                $color = $cell['color'];
            } elseif ($color !== $cell['color']) {
                $this->warn('A table uses several border colours; Notes shows all cell borders of a table in one colour.');
            }
        }

        $cols = $this->columnWidths($cells, $first, $last, $ncols, $tableWidth);

        $rows = [];
        for ($row = $first; $row <= $last; $row++) {
            $line = [];
            for ($c = 0; $c < $ncols; $c++) {
                $idx = $grid[$row][$c] ?? null;
                if ($idx === null) {
                    $line[] = ['empty' => true];
                    continue;
                }
                $cell = $cells[$idx];
                if ($cell['r'] !== $row || $cell['c'] !== $c) {
                    continue;                           // covered by a span
                }
                $cell['rs'] = min($cell['rs'], $last - $row + 1);
                $cell['cs'] = min($cell['cs'], $ncols - $c);
                $line[] = $cell;
            }
            $rows[] = $line;
        }

        $align = 'left';
        $a = $this->alignment($table->getAttribute('align'));
        if ($a !== null) {
            $align = $a;
        } elseif (strtolower($style['margin-left'] ?? '') === 'auto' && strtolower($style['margin-right'] ?? '') === 'auto') {
            $align = 'center';
        }
        return ['type' => 'table', 'indent' => $ctx['indent'], 'align' => $align, 'cols' => $cols, 'rows' => $rows,
                'color' => $color ?? '#000000', 'bg' => $tableBg];
    }

    /**
     * Estimated widths of the content: preferred (no wrapping) and minimum
     * (widest picture or word), in pixels.
     *
     * @return array{0: float, 1: float}
     */
    private function measure(array $blocks): array
    {
        $pref = 0.0;
        $min = 0.0;
        foreach ($blocks as $block) {
            $indent = (float)($block['indent'] ?? 0.0);
            if ($block['type'] === 'table') {
                $w = array_sum($block['cols']);
                $pref = max($pref, $w + $indent);
                $min = max($min, $w + $indent);
                continue;
            }
            if ($block['type'] !== 'par') {
                continue;
            }
            $list = $block['list'] !== 'none' ? 18.0 : 0.0;
            $line = 0.0;
            $leaves = [];
            foreach ($block['items'] as $item) {
                if ($item['k'] === 'link') {
                    foreach ($item['items'] as $sub) {
                        $leaves[] = $sub;
                    }
                } else {
                    $leaves[] = $item;
                }
            }
            foreach ($leaves as $item) {
                if ($item['k'] === 'br') {
                    $pref = max($pref, $line + $indent + $list);
                    $line = 0.0;
                } elseif ($item['k'] === 'img') {
                    $line += $item['w'];
                    $min = max($min, $item['w'] + $indent + $list);
                } elseif ($item['k'] === 'text') {
                    $line += $this->textWidth($item['text'], $item['f']);
                    foreach (preg_split('/ +/', $item['text']) ?: [] as $word) {
                        $min = max($min, $this->textWidth($word, $item['f']) + $indent + $list);
                    }
                }
            }
            $pref = max($pref, $line + $indent + $list);
        }
        return [$pref, $min];
    }

    /** Rough width of a text in pixels (generous, so that Notes does not wrap). */
    private function textWidth(string $text, array $font): float
    {
        $px = $font['size'] * 96 / 72;
        $factor = $font['bold'] ? 0.64 : 0.58;
        if (stripos($font['name'], 'courier') !== false) {
            $factor = 0.62;
        }
        return mb_strlen($text, 'UTF-8') * $px * $factor;
    }

    /** @return float[] column widths in pixels */
    private function columnWidths(array $cells, int $first, int $last, int $ncols, ?float $tableWidth): array
    {
        $width = array_fill(0, $ncols, 0.0);
        $min = array_fill(0, $ncols, 0.0);
        $fixed = array_fill(0, $ncols, null);
        $spanned = [];
        foreach ($cells as $cell) {
            if ($cell['r'] < $first || $cell['r'] > $last) {
                continue;
            }
            [$pref, $cmin] = $this->measure($cell['blocks']);
            // Left padding (at least Notes' small cell margin), right padding, a little air.
            $extra = max(3.0, $cell['pad'][3]) + $cell['pad'][1] + 6.0;
            $pref += $extra;
            $cmin += $extra;
            $cs = min($cell['cs'], $ncols - $cell['c']);
            if ($cs === 1) {
                $c = $cell['c'];
                $width[$c] = max($width[$c], $pref);
                $min[$c] = max($min[$c], $cmin);
                if ($cell['width'] !== null) {
                    $fixed[$c] = max($fixed[$c] ?? 0.0, $cell['width']);
                }
            } else {
                $spanned[] = [$cell['c'], $cs, $cell['width'] !== null ? max($cell['width'], $cmin) : $pref];
            }
        }
        for ($c = 0; $c < $ncols; $c++) {
            if ($fixed[$c] !== null) {
                $width[$c] = max($fixed[$c], $min[$c]);
            }
        }
        foreach ($spanned as [$c, $cs, $need]) {
            $have = array_sum(array_slice($width, $c, $cs));
            if ($need > $have) {
                for ($j = $c; $j < $c + $cs; $j++) {
                    $width[$j] += ($need - $have) / $cs;
                }
            }
        }
        $sum = array_sum($width);
        $free = array_keys(array_filter($fixed, function ($v) {
            return $v === null;
        }));
        if ($tableWidth !== null && $tableWidth > 0) {
            $target = min($tableWidth, NOTES_DXL_MAX_TABLE_WIDTH);
            if ($sum < $target) {
                $targets = $free ?: range(0, $ncols - 1);
                $base = 0.0;
                foreach ($targets as $c) {
                    $base += $width[$c];
                }
                foreach ($targets as $c) {
                    $width[$c] += ($target - $sum) * ($base > 0 ? $width[$c] / $base : 1 / count($targets));
                }
            } elseif ($sum > $target) {
                $this->shrink($width, $min, $free ?: range(0, $ncols - 1), $sum - $target);
            }
        }
        $sum = array_sum($width);
        if ($sum > NOTES_DXL_MAX_TABLE_WIDTH) {
            $this->shrink($width, $min, range(0, $ncols - 1), $sum - NOTES_DXL_MAX_TABLE_WIDTH);
        }
        return array_map(function ($w) {
            return max(8.0, round($w));
        }, $width);
    }

    /** Takes $excess pixels from the given columns, never below their minimum. */
    private function shrink(array &$width, array $min, array $cols, float $excess): void
    {
        $room = 0.0;
        foreach ($cols as $c) {
            $room += max(0.0, $width[$c] - $min[$c]);
        }
        if ($room <= 0) {
            return;
        }
        $take = min(1.0, $excess / $room);
        foreach ($cols as $c) {
            $width[$c] -= max(0.0, $width[$c] - $min[$c]) * $take;
        }
    }

    private function warn(string $message): void
    {
        $this->warnings[$message] = true;
    }

    // -----------------------------------------------------------------
    // Serialisation
    // -----------------------------------------------------------------

    /** Inches with at most four decimals, e.g. "1.5in". */
    private function inches(float $px): string
    {
        return rtrim(rtrim(sprintf('%.4F', $px / 96), '0'), '.') . 'in';
    }

    /**
     * $cellMargin: null for the signature itself (Notes' own left margin of
     * 1 inch applies), else the cell's left padding in pixels.
     */
    private function serializeBlocks(array $blocks, ?float $cellMargin): string
    {
        $out = '';
        $pardefs = [];
        foreach ($blocks as $block) {
            $indent = (float)($block['indent'] ?? 0.0);
            if ($block['type'] === 'table') {
                $out .= $this->serializeTable($block, $cellMargin, $indent);
                continue;
            }
            $attrs = [];
            if ($block['type'] === 'par' && $block['align'] !== 'left') {
                $attrs['align'] = $block['align'];
            }
            $left = $this->leftMargin($cellMargin, $indent + (($block['type'] === 'par' && $block['list'] !== 'none') ? 18.0 : 0.0));
            if ($left !== null) {
                $attrs['leftmargin'] = $left;
            }
            if ($block['type'] === 'par') {
                if ($block['before'] !== '1') {
                    $attrs['spacebefore'] = $block['before'];
                }
                if ($block['after'] !== '1') {
                    $attrs['spaceafter'] = $block['after'];
                }
                if ($block['list'] !== 'none') {
                    $attrs['list'] = $block['list'];
                }
            }
            $key = http_build_query($attrs);
            $def = '';
            if (!isset($pardefs[$key])) {
                $pardefs[$key] = ++$this->pardefSeq;
                $def = '<pardef id=\'' . $pardefs[$key] . '\'';
                foreach ($attrs as $name => $value) {
                    $def .= ' ' . $name . '=\'' . $this->attr((string)$value) . '\'';
                }
                $def .= " keepwithnext='true' keeptogether='true'/>\n";
            }
            $out .= $def . '<par def=\'' . $pardefs[$key] . '\'>';
            if ($block['type'] === 'spacer') {
                $out .= '<run><font size=\'' . (int)$block['size'] . "pt'/></run>";
            } elseif (count($block['items']) === 1 && $block['items'][0]['k'] === 'br') {
                $out .= '<run>' . $this->fontTag($block['items'][0]['f']) . '</run>';   // one empty line
            } else {
                $out .= $this->serializeInline($block['items']);
            }
            $out .= "</par>\n";
        }
        return $out;
    }

    private function leftMargin(?float $cellMargin, float $indent): ?string
    {
        if ($cellMargin === null) {
            return $indent > 0 ? $this->inches(96 + $indent) : null;
        }
        return $this->inches(max(3.0, $cellMargin) + $indent);
    }

    private function serializeInline(array $items): string
    {
        $out = '';
        foreach ($items as $item) {
            switch ($item['k']) {
                case 'text':
                    $out .= '<run>' . $this->fontTag($item['f']) . $this->text($item['text']) . '</run>';
                    break;
                case 'br':
                    $out .= '<run>' . $this->fontTag($item['f']) . '<break/></run>';
                    break;
                case 'img':
                    $out .= '<picture width=\'' . (int)$item['w'] . 'px\' height=\'' . (int)$item['h'] . 'px\''
                          . ($item['alt'] !== '' ? ' alttext=\'' . $this->attr($item['alt']) . '\'' : '') . '>'
                          . '<' . $item['format'] . ">\n" . chunk_split($item['data'], 76, "\n")
                          . '</' . $item['format'] . '></picture>';
                    break;
                case 'link':
                    if ($item['items']) {
                        $out .= '<urllink showborder=\'false\' href=\'' . $this->attr($item['href']) . '\'>'
                              . $this->serializeInline($item['items']) . '</urllink>';
                    }
                    break;
                case 'hr':
                    $out .= '<horizrule height=\'' . $this->inches($item['height']) . '\' width=\'' . $this->attr($item['width'])
                          . '\' color=\'' . $item['color'] . "' use3dshading='false'/>";
                    break;
            }
        }
        return $out;
    }

    private function serializeTable(array $t, ?float $cellMargin, float $indent): string
    {
        $widthType = ['left' => 'fixedleft', 'center' => 'fixedcenter', 'right' => 'fixedright', 'full' => 'fixedleft'][$t['align']] ?? 'fixedleft';
        $out = '<table widthtype=\'' . $widthType . '\'';
        $left = $this->leftMargin($cellMargin, $indent);
        if ($left !== null && $widthType === 'fixedleft') {
            $out .= ' leftmargin=\'' . $left . '\'';
        }
        $out .= ' cellbordercolor=\'' . $t['color'] . "' cellborderstyle='solid'";
        if ($t['bg'] !== null) {
            $out .= " colorstyle='solid' bgcolor='" . $t['bg'] . "'";
        }
        $out .= " columnspacing='0in' rowspacing='0in'>\n";
        foreach ($t['cols'] as $w) {
            $out .= '<tablecolumn width=\'' . $this->inches($w) . "'/>\n";
        }
        foreach ($t['rows'] as $row) {
            $out .= "<tablerow>\n";
            foreach ($row as $cell) {
                if (!empty($cell['empty'])) {
                    $out .= "<tablecell borderwidth='0px'>\n" . $this->serializeBlocks([['type' => 'spacer', 'size' => 1, 'indent' => 0.0]], 3.0) . "</tablecell>\n";
                    continue;
                }
                $out .= '<tablecell';
                if ($cell['cs'] > 1) {
                    $out .= ' columnspan=\'' . (int)$cell['cs'] . '\'';
                }
                if ($cell['rs'] > 1) {
                    $out .= ' rowspan=\'' . (int)$cell['rs'] . '\'';
                }
                $b = $cell['borders'];
                $bw = ($b[0] == $b[1] && $b[1] == $b[2] && $b[2] == $b[3])
                    ? (int)$b[0] . 'px'
                    : (int)$b[0] . 'px ' . (int)$b[1] . 'px ' . (int)$b[2] . 'px ' . (int)$b[3] . 'px';
                $out .= ' borderwidth=\'' . $bw . '\' valign=\'' . $cell['valign'] . '\'';
                if ($cell['bg'] !== null) {
                    $out .= ' bgcolor=\'' . $cell['bg'] . '\'';
                }
                $out .= ">\n";
                $blocks = $cell['blocks'] ?: [['type' => 'spacer', 'size' => 1, 'indent' => 0.0]];
                $out .= $this->serializeBlocks($blocks, $cell['pad'][3]);
                $out .= "</tablecell>\n";
            }
            $out .= "</tablerow>\n";
        }
        return $out . "</table>\n";
    }

    private function fontTag(array $f): string
    {
        $size = max(1, (int)round($f['size']));
        $out = '<font size=\'' . $size . 'pt\' name=\'' . $this->attr($f['name']) . '\'';
        $styles = [];
        foreach (['bold' => 'bold', 'italic' => 'italic', 'underline' => 'underline', 'strike' => 'strikethrough',
                  'sup' => 'superscript', 'sub' => 'subscript'] as $key => $token) {
            if ($f[$key]) {
                $styles[] = $token;
            }
        }
        if ($styles) {
            $out .= ' style=\'' . implode(' ', $styles) . '\'';
        }
        if ($f['color'] !== null) {
            $out .= ' color=\'' . $f['color'] . '\'';
        }
        return $out . '/>';
    }

    /** Text content: only characters XML allows, escaped. */
    private function text(string $s): string
    {
        return htmlspecialchars(notesDxlXmlChars($s), ENT_NOQUOTES | ENT_XML1, 'UTF-8');
    }

    /** Attribute value (single-quoted): only characters XML allows, escaped. */
    private function attr(string $s): string
    {
        $s = str_replace(["\t", "\n", "\r"], ' ', notesDxlXmlChars($s));
        return htmlspecialchars($s, ENT_QUOTES | ENT_XML1, 'UTF-8');
    }
}

/**
 * Removes characters that are not allowed in XML 1.0 (and invalid UTF-8).
 */
function notesDxlXmlChars(string $s): string
{
    $s = mb_scrub($s, 'UTF-8');
    return (string)preg_replace('/[^\x{9}\x{A}\x{D}\x{20}-\x{D7FF}\x{E000}-\x{FFFD}\x{10000}-\x{10FFFF}]/u', '', $s);
}

/**
 * Final check of a result: well-formed XML, a single <richtext> root, only
 * allowed elements, no comments/processing instructions/CDATA/DOCTYPE/entities
 * beyond the five predefined ones, and only http(s)/mailto/tel links.
 *
 * @throws RuntimeException
 */
function notesDxlSelfCheck(string $dxl): void
{
    if (preg_match('/<[!?]/', $dxl)) {
        throw new RuntimeException('Notes DXL check failed: markup declaration found.');
    }
    if (preg_match('/&(?!(?:amp|lt|gt|apos|quot);)/', $dxl)) {
        throw new RuntimeException('Notes DXL check failed: unexpected entity reference.');
    }
    if (!preg_match_all('#<\s*/?\s*([A-Za-z_][A-Za-z0-9_.:\-]*)#', $dxl, $m)) {
        throw new RuntimeException('Notes DXL check failed: no elements.');
    }
    $allowed = array_flip(NOTES_DXL_ALLOWED_ELEMENTS);
    foreach ($m[1] as $name) {
        if (!isset($allowed[strtolower($name)])) {
            throw new RuntimeException('Notes DXL check failed: element <' . $name . '> is not allowed.');
        }
    }
    if (preg_match_all('/\bhref=([\'"])(.*?)\1/s', $dxl, $links)) {
        foreach ($links[2] as $href) {
            if (!preg_match('#^(?:https?://|mailto:|tel:)#i', html_entity_decode($href, ENT_QUOTES | ENT_XML1, 'UTF-8'))) {
                throw new RuntimeException('Notes DXL check failed: link scheme not allowed.');
            }
        }
    }
    $doc = new DOMDocument();
    $previous = libxml_use_internal_errors(true);
    $ok = $doc->loadXML($dxl, LIBXML_NONET);
    libxml_clear_errors();
    libxml_use_internal_errors($previous);
    if (!$ok || !$doc->documentElement || $doc->documentElement->nodeName !== 'richtext') {
        throw new RuntimeException('Notes DXL check failed: the result is not well-formed.');
    }
}
