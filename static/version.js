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
    });
})();
