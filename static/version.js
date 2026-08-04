// Wellness Ping easter egg:
//  - Tap the version number to copy it.
//  - Keep tapping (> 3 times) and it turns into a random kaomoji, changing
//    every tap after that.
(function () {
    var KAOMOJI = [
        "( ^_^)o自自o(^_^ )",
        "( ˘ ³˘)♥",
        "(ノ◕ヮ◕)ノ*:･ﾟ✧",
        "┬─┬ノ( º _ ºノ)",
        "(╯°□°)╯︵ ┻━┻",
        "(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧",
        "⊂(・▽・⊂)",
        "(づ｡◕‿‿◕｡)づ",
        "(๑˃̵ᴗ˂̵)و",
        "ᕕ( ᐛ )ᕗ",
        "(∩ᄑ_ᄑ)⊃━☆ﾟ*･｡ﾟ",
        "¯\\_(ツ)_/¯",
        "( ͡° ͜ʖ ͡°)",
        "(ᵔᴥᵔ)",
        "≧◡≦",
        "(￣▽￣)",
        "ᕙ(⇀‸↼‶)ᕗ",
        "ʕ •ᴥ•ʔ",
        "ʕ ︵ ʔ",
        "ฅ^•ﻌ•^ฅ",
        "^•ﻌ•^",
        "ᕦ(ò_óˇ)ᕤ",
        "(づ￣ ³￣)づ",
        "(っ˘ڡ˘ς)",
        "(｡♥‿♥｡)",
        "(^・ω・^ )",
        "(´⊙ω⊙`)",
        "( ノωヽ)",
        "(´・ω・`)",
        "（；´д｀)",
        "(；￣Д￣)",
        "(-ω- )",
        "(´｡• ᵕ •｡`)",
        "(๑>؂<๑)",
        "( •̀ᴗ•́ )و",
        "ʕ ・ᴥ・ʔ",
        "(￢_￢)",
        "( ¬_¬ )",
        "ヽ(´▽`)/",
        "ヾ(⌐■_■)ノ♪",
        "ヾ(●´∀｀●)",
        "(ﾉ´ヮ`)ﾉ*: ･ﾟ",
        "o(〃＾▽＾〃)o",
        "(n˘v˘•)¬",
        "(ミ ◕‿◕ 彡)",
        "ヘ(￣ω￣ヘ)",
        "(⊙﹏⊙)",
        "(╥﹏╥)",
        "(◕‿◕)",
        "(•_•) >⌐■-■ (⌐■_■)",
        "┐(´д｀)┌",
        "＼(^o^)／",
        "(ﾉ≧∇≦)ﾉ",
        "(・∀・)",
        "(。・∀・。)ノ",
        "m9(＾Д＾)",
        "(・_・;)",
        "(￣□￣」)",
        "(´｡• ᵕ •｡`) ♡",
        "❤ (ɔˆз(ˆ⌣ˆc)",
        "(づ｡◕‿‿◕｡)づ ♥"
    ];

    var presses = 0;

    function copyText(txt) {
        var done = function () {};
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(txt).catch(done);
        } else {
            done();
        }
    }

    document.addEventListener('DOMContentLoaded', function () {
        var els = document.querySelectorAll('.version');
        Array.prototype.forEach.call(els, function (el) {
            el.style.cursor = 'pointer';
            el.style.display = 'inline-block';
            el.addEventListener('click', function (ev) {
                ev.preventDefault();
                presses += 1;
                if (presses > 3) {
                    var k = KAOMOJI[Math.floor(Math.random() * KAOMOJI.length)];
                    el.textContent = k;
                    copyText(k);
                } else {
                    copyText(el.textContent.trim());
                }
            });
        });

        wireKeySequence();
    });

    // A little something for the keyboard-inclined. Ignored while typing in
    // form fields so it never fires from normal input.
    var SEQUENCE = ['ArrowUp','ArrowUp','ArrowDown','ArrowDown','ArrowLeft','ArrowRight','ArrowLeft','ArrowRight','b','a'];
    var seqPos = 0;

    function wireKeySequence() {
        document.addEventListener('keydown', function (ev) {
            var t = ev.target;
            if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT')) {
                seqPos = 0;
                return;
            }
            var key = ev.key;
            if (key === SEQUENCE[seqPos]) {
                seqPos += 1;
                if (seqPos === SEQUENCE.length) {
                    seqPos = 0;
                    tableFlip();
                }
            } else {
                seqPos = (key === SEQUENCE[0]) ? 1 : 0;
            }
        });
    }

    function tableFlip() {
        var flips = [
            '(╯°□°）╯︵ ┻━┻',
            '(ノ°Д°）ノ︵ ┻━┻',
            '(╯°□°）╯︵ ┴─┴',
            '(ノ ゜Д゜)ノ ︵ ┻━┻',
            '╯︵ ┻━┻ ︵ ┬─┬ ／(.○.）＼',
            '(╯‵□′)╯︵┻━┻',
            '┻━┻︵ ヽ(´Д`。)ノ︵ ┻━┻'
        ];
        var box = document.createElement('div');
        box.textContent = flips[Math.floor(Math.random() * flips.length)];
        box.style.cssText = 'position:fixed;inset:0;display:flex;align-items:center;justify-content:center;' +
            'text-align:center;font-size:24px;line-height:1.6;background:rgba(0,0,0,0.85);color:#fff;' +
            'z-index:99999;cursor:pointer;padding:20px;';
        box.addEventListener('click', function () { box.remove(); });
        document.body.appendChild(box);
    }
})();
