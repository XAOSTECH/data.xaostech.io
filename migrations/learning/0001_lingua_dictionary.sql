-- =============================================================================
-- XAOSTECH Lingua - Dictionary D1 Migration
-- =============================================================================
-- Migrates static dictionary data to D1 for scalability and dynamic updates.
-- Supports multilingual translations, etymology, and part-of-speech data.
-- =============================================================================

-- =============================================================================
-- CORE DICTIONARY TABLE
-- =============================================================================
CREATE TABLE IF NOT EXISTS dictionary_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    word TEXT NOT NULL UNIQUE,
    translations_json TEXT NOT NULL, -- JSON object: { "es": "hola", "fr": "bonjour", ... }
    etymology_json TEXT,             -- JSON object with etymology data (optional)
    pos TEXT,                        -- Part of speech: noun, verb, adjective, etc.
    frequency INTEGER DEFAULT 999,   -- Usage frequency rank (1 = most common)
    variants_json TEXT,              -- JSON array of alternate forms
    source_language TEXT DEFAULT 'en',
    is_core BOOLEAN DEFAULT 1,       -- Core dictionary vs learned words
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for efficient lookups
CREATE INDEX IF NOT EXISTS idx_dictionary_word ON dictionary_entries(word);
CREATE INDEX IF NOT EXISTS idx_dictionary_pos ON dictionary_entries(pos);
CREATE INDEX IF NOT EXISTS idx_dictionary_frequency ON dictionary_entries(frequency);
CREATE INDEX IF NOT EXISTS idx_dictionary_is_core ON dictionary_entries(is_core);

-- =============================================================================
-- LEARNED WORDS TABLE (for AI-generated translations)
-- =============================================================================
CREATE TABLE IF NOT EXISTS learned_words (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    word TEXT NOT NULL,
    target_language TEXT NOT NULL,
    translation TEXT NOT NULL,
    confidence REAL DEFAULT 0.9,
    source TEXT DEFAULT 'ai',        -- ai, user, import
    verified BOOLEAN DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(word, target_language)
);

CREATE INDEX IF NOT EXISTS idx_learned_word ON learned_words(word);
CREATE INDEX IF NOT EXISTS idx_learned_language ON learned_words(target_language);

-- =============================================================================
-- SEED DATA - Core Dictionary (Top 200+ words)
-- =============================================================================

-- Greetings & Common Phrases
INSERT OR IGNORE INTO dictionary_entries (word, translations_json, etymology_json, pos, frequency) VALUES
('hello', '{"es":"hola","fr":"bonjour","de":"hallo","it":"ciao","pt":"olá","ja":"こんにちは","zh":"你好","ko":"안녕하세요","ar":"مرحبا","ru":"привет"}', '{"origin":"Old English","originalForm":"hǣl","meaning":"health, wholeness","root":"*hailaz","rootLanguage":"Proto-Germanic","cognates":[{"word":"heil","language":"German"},{"word":"heel","language":"Dutch"}],"firstUse":"1826 (as greeting)"}', 'interjection', 1),
('goodbye', '{"es":"adiós","fr":"au revoir","de":"auf wiedersehen","it":"arrivederci","pt":"adeus","ja":"さようなら","zh":"再见","ko":"안녕히 가세요","ar":"مع السلامة","ru":"до свидания"}', '{"origin":"English","originalForm":"God be with ye","meaning":"God be with you","firstUse":"1570s"}', 'interjection', 2),
('yes', '{"es":"sí","fr":"oui","de":"ja","it":"sì","pt":"sim","ja":"はい","zh":"是","ko":"네","ar":"نعم","ru":"да"}', '{"origin":"Old English","originalForm":"gēse","meaning":"so be it","root":"*gea swa","rootLanguage":"Proto-Germanic"}', 'adverb', 3),
('no', '{"es":"no","fr":"non","de":"nein","it":"no","pt":"não","ja":"いいえ","zh":"不","ko":"아니요","ar":"لا","ru":"нет"}', '{"origin":"Old English","originalForm":"nā","meaning":"not ever","root":"*ne","rootLanguage":"Proto-Indo-European"}', 'adverb', 4),
('please', '{"es":"por favor","fr":"s''il vous plaît","de":"bitte","it":"per favore","pt":"por favor","ja":"お願いします","zh":"请","ko":"제발","ar":"من فضلك","ru":"пожалуйста"}', '{"origin":"Old French","originalForm":"plaisir","meaning":"to please","root":"placere","rootLanguage":"Latin"}', 'adverb', 5),
('thank you', '{"es":"gracias","fr":"merci","de":"danke","it":"grazie","pt":"obrigado","ja":"ありがとう","zh":"谢谢","ko":"감사합니다","ar":"شكرا","ru":"спасибо"}', '{"origin":"Old English","originalForm":"þancian","meaning":"to give thanks","root":"*þankaz","rootLanguage":"Proto-Germanic"}', 'phrase', 6),
('thanks', '{"es":"gracias","fr":"merci","de":"danke","it":"grazie","pt":"obrigado","ja":"ありがとう","zh":"谢谢","ko":"감사합니다","ar":"شكرا","ru":"спасибо"}', NULL, 'noun', 7);

-- Pronouns
INSERT OR IGNORE INTO dictionary_entries (word, translations_json, etymology_json, pos, frequency) VALUES
('i', '{"es":"yo","fr":"je","de":"ich","it":"io","pt":"eu","ja":"私","zh":"我","ko":"나","ar":"أنا","ru":"я"}', '{"origin":"Old English","originalForm":"ic","root":"*éǵh₂","rootLanguage":"Proto-Indo-European"}', 'pronoun', 8),
('you', '{"es":"tú","fr":"tu/vous","de":"du/Sie","it":"tu/Lei","pt":"tu/você","ja":"あなた","zh":"你","ko":"너/당신","ar":"أنت","ru":"ты/вы"}', '{"origin":"Old English","originalForm":"ēow","root":"*jūz","rootLanguage":"Proto-Germanic"}', 'pronoun', 9),
('he', '{"es":"él","fr":"il","de":"er","it":"lui","pt":"ele","ja":"彼","zh":"他","ko":"그","ar":"هو","ru":"он"}', NULL, 'pronoun', 10),
('she', '{"es":"ella","fr":"elle","de":"sie","it":"lei","pt":"ela","ja":"彼女","zh":"她","ko":"그녀","ar":"هي","ru":"она"}', NULL, 'pronoun', 11),
('it', '{"es":"eso","fr":"ça/il/elle","de":"es","it":"esso","pt":"isso","ja":"それ","zh":"它","ko":"그것","ar":"هو/هي","ru":"оно"}', NULL, 'pronoun', 12),
('we', '{"es":"nosotros","fr":"nous","de":"wir","it":"noi","pt":"nós","ja":"私たち","zh":"我们","ko":"우리","ar":"نحن","ru":"мы"}', NULL, 'pronoun', 13),
('they', '{"es":"ellos","fr":"ils/elles","de":"sie","it":"loro","pt":"eles","ja":"彼ら","zh":"他们","ko":"그들","ar":"هم","ru":"они"}', NULL, 'pronoun', 14);

-- Common Verbs
INSERT OR IGNORE INTO dictionary_entries (word, translations_json, etymology_json, pos, frequency) VALUES
('be', '{"es":"ser/estar","fr":"être","de":"sein","it":"essere","pt":"ser/estar","ja":"です/いる","zh":"是","ko":"이다","ar":"يكون","ru":"быть"}', '{"origin":"Old English","originalForm":"bēon","root":"*bʰuH-","rootLanguage":"Proto-Indo-European","meaning":"to grow, become"}', 'verb', 15),
('have', '{"es":"tener","fr":"avoir","de":"haben","it":"avere","pt":"ter","ja":"持つ","zh":"有","ko":"가지다","ar":"يملك","ru":"иметь"}', '{"origin":"Old English","originalForm":"habban","root":"*habēną","rootLanguage":"Proto-Germanic"}', 'verb', 16),
('do', '{"es":"hacer","fr":"faire","de":"tun/machen","it":"fare","pt":"fazer","ja":"する","zh":"做","ko":"하다","ar":"يفعل","ru":"делать"}', NULL, 'verb', 17),
('say', '{"es":"decir","fr":"dire","de":"sagen","it":"dire","pt":"dizer","ja":"言う","zh":"说","ko":"말하다","ar":"يقول","ru":"сказать"}', NULL, 'verb', 18),
('go', '{"es":"ir","fr":"aller","de":"gehen","it":"andare","pt":"ir","ja":"行く","zh":"去","ko":"가다","ar":"يذهب","ru":"идти"}', '{"origin":"Old English","originalForm":"gān","root":"*ǵʰeh₁-","rootLanguage":"Proto-Indo-European","meaning":"to go, leave"}', 'verb', 19),
('get', '{"es":"obtener","fr":"obtenir","de":"bekommen","it":"ottenere","pt":"obter","ja":"得る","zh":"得到","ko":"얻다","ar":"يحصل","ru":"получать"}', NULL, 'verb', 20),
('make', '{"es":"hacer","fr":"faire","de":"machen","it":"fare","pt":"fazer","ja":"作る","zh":"做","ko":"만들다","ar":"يصنع","ru":"делать"}', NULL, 'verb', 21),
('know', '{"es":"saber/conocer","fr":"savoir/connaître","de":"wissen/kennen","it":"sapere/conoscere","pt":"saber/conhecer","ja":"知る","zh":"知道","ko":"알다","ar":"يعرف","ru":"знать"}', NULL, 'verb', 22),
('think', '{"es":"pensar","fr":"penser","de":"denken","it":"pensare","pt":"pensar","ja":"思う","zh":"想","ko":"생각하다","ar":"يفكر","ru":"думать"}', NULL, 'verb', 23),
('take', '{"es":"tomar","fr":"prendre","de":"nehmen","it":"prendere","pt":"pegar","ja":"取る","zh":"拿","ko":"가지다","ar":"يأخذ","ru":"брать"}', NULL, 'verb', 24),
('see', '{"es":"ver","fr":"voir","de":"sehen","it":"vedere","pt":"ver","ja":"見る","zh":"看","ko":"보다","ar":"يرى","ru":"видеть"}', NULL, 'verb', 25),
('come', '{"es":"venir","fr":"venir","de":"kommen","it":"venire","pt":"vir","ja":"来る","zh":"来","ko":"오다","ar":"يأتي","ru":"приходить"}', NULL, 'verb', 26),
('want', '{"es":"querer","fr":"vouloir","de":"wollen","it":"volere","pt":"querer","ja":"欲しい","zh":"想要","ko":"원하다","ar":"يريد","ru":"хотеть"}', NULL, 'verb', 27),
('use', '{"es":"usar","fr":"utiliser","de":"benutzen","it":"usare","pt":"usar","ja":"使う","zh":"使用","ko":"사용하다","ar":"يستخدم","ru":"использовать"}', NULL, 'verb', 28),
('find', '{"es":"encontrar","fr":"trouver","de":"finden","it":"trovare","pt":"encontrar","ja":"見つける","zh":"找到","ko":"찾다","ar":"يجد","ru":"находить"}', NULL, 'verb', 29),
('give', '{"es":"dar","fr":"donner","de":"geben","it":"dare","pt":"dar","ja":"あげる","zh":"给","ko":"주다","ar":"يعطي","ru":"давать"}', NULL, 'verb', 30),
('tell', '{"es":"contar","fr":"raconter","de":"erzählen","it":"raccontare","pt":"contar","ja":"教える","zh":"告诉","ko":"말하다","ar":"يخبر","ru":"рассказывать"}', NULL, 'verb', 31),
('work', '{"es":"trabajar","fr":"travailler","de":"arbeiten","it":"lavorare","pt":"trabalhar","ja":"働く","zh":"工作","ko":"일하다","ar":"يعمل","ru":"работать"}', NULL, 'verb', 32),
('call', '{"es":"llamar","fr":"appeler","de":"anrufen","it":"chiamare","pt":"chamar","ja":"呼ぶ","zh":"叫","ko":"부르다","ar":"يتصل","ru":"звонить"}', NULL, 'verb', 33),
('try', '{"es":"intentar","fr":"essayer","de":"versuchen","it":"provare","pt":"tentar","ja":"試す","zh":"尝试","ko":"시도하다","ar":"يحاول","ru":"пытаться"}', NULL, 'verb', 34),
('need', '{"es":"necesitar","fr":"avoir besoin","de":"brauchen","it":"aver bisogno","pt":"precisar","ja":"必要とする","zh":"需要","ko":"필요하다","ar":"يحتاج","ru":"нуждаться"}', NULL, 'verb', 35),
('feel', '{"es":"sentir","fr":"sentir","de":"fühlen","it":"sentire","pt":"sentir","ja":"感じる","zh":"感觉","ko":"느끼다","ar":"يشعر","ru":"чувствовать"}', NULL, 'verb', 36),
('become', '{"es":"convertirse","fr":"devenir","de":"werden","it":"diventare","pt":"tornar-se","ja":"なる","zh":"成为","ko":"되다","ar":"يصبح","ru":"становиться"}', NULL, 'verb', 37),
('leave', '{"es":"dejar","fr":"partir","de":"verlassen","it":"lasciare","pt":"deixar","ja":"去る","zh":"离开","ko":"떠나다","ar":"يغادر","ru":"уходить"}', NULL, 'verb', 38),
('put', '{"es":"poner","fr":"mettre","de":"legen","it":"mettere","pt":"colocar","ja":"置く","zh":"放","ko":"놓다","ar":"يضع","ru":"класть"}', NULL, 'verb', 39),
('mean', '{"es":"significar","fr":"signifier","de":"bedeuten","it":"significare","pt":"significar","ja":"意味する","zh":"意味着","ko":"의미하다","ar":"يعني","ru":"означать"}', NULL, 'verb', 40),
('keep', '{"es":"mantener","fr":"garder","de":"behalten","it":"tenere","pt":"manter","ja":"保つ","zh":"保持","ko":"유지하다","ar":"يحافظ","ru":"держать"}', NULL, 'verb', 41),
('let', '{"es":"dejar","fr":"laisser","de":"lassen","it":"lasciare","pt":"deixar","ja":"させる","zh":"让","ko":"허락하다","ar":"يدع","ru":"позволять"}', NULL, 'verb', 42),
('begin', '{"es":"empezar","fr":"commencer","de":"beginnen","it":"cominciare","pt":"começar","ja":"始める","zh":"开始","ko":"시작하다","ar":"يبدأ","ru":"начинать"}', NULL, 'verb', 43),
('seem', '{"es":"parecer","fr":"sembler","de":"scheinen","it":"sembrare","pt":"parecer","ja":"見える","zh":"似乎","ko":"보이다","ar":"يبدو","ru":"казаться"}', NULL, 'verb', 44),
('help', '{"es":"ayudar","fr":"aider","de":"helfen","it":"aiutare","pt":"ajudar","ja":"助ける","zh":"帮助","ko":"돕다","ar":"يساعد","ru":"помогать"}', NULL, 'verb', 45),
('show', '{"es":"mostrar","fr":"montrer","de":"zeigen","it":"mostrare","pt":"mostrar","ja":"見せる","zh":"展示","ko":"보여주다","ar":"يظهر","ru":"показывать"}', NULL, 'verb', 46),
('hear', '{"es":"oír","fr":"entendre","de":"hören","it":"sentire","pt":"ouvir","ja":"聞く","zh":"听","ko":"듣다","ar":"يسمع","ru":"слышать"}', NULL, 'verb', 47),
('play', '{"es":"jugar","fr":"jouer","de":"spielen","it":"giocare","pt":"jogar","ja":"遊ぶ","zh":"玩","ko":"놀다","ar":"يلعب","ru":"играть"}', NULL, 'verb', 48),
('run', '{"es":"correr","fr":"courir","de":"laufen","it":"correre","pt":"correr","ja":"走る","zh":"跑","ko":"달리다","ar":"يركض","ru":"бегать"}', NULL, 'verb', 49),
('move', '{"es":"mover","fr":"bouger","de":"bewegen","it":"muovere","pt":"mover","ja":"動く","zh":"移动","ko":"움직이다","ar":"يتحرك","ru":"двигаться"}', NULL, 'verb', 50),
('live', '{"es":"vivir","fr":"vivre","de":"leben","it":"vivere","pt":"viver","ja":"住む","zh":"住","ko":"살다","ar":"يعيش","ru":"жить"}', NULL, 'verb', 51),
('believe', '{"es":"creer","fr":"croire","de":"glauben","it":"credere","pt":"acreditar","ja":"信じる","zh":"相信","ko":"믿다","ar":"يؤمن","ru":"верить"}', NULL, 'verb', 52),
('hold', '{"es":"sostener","fr":"tenir","de":"halten","it":"tenere","pt":"segurar","ja":"持つ","zh":"握","ko":"잡다","ar":"يمسك","ru":"держать"}', NULL, 'verb', 53),
('bring', '{"es":"traer","fr":"apporter","de":"bringen","it":"portare","pt":"trazer","ja":"持ってくる","zh":"带来","ko":"가져오다","ar":"يجلب","ru":"приносить"}', NULL, 'verb', 54),
('write', '{"es":"escribir","fr":"écrire","de":"schreiben","it":"scrivere","pt":"escrever","ja":"書く","zh":"写","ko":"쓰다","ar":"يكتب","ru":"писать"}', NULL, 'verb', 55),
('stand', '{"es":"estar de pie","fr":"se tenir","de":"stehen","it":"stare in piedi","pt":"ficar de pé","ja":"立つ","zh":"站","ko":"서다","ar":"يقف","ru":"стоять"}', NULL, 'verb', 56),
('sit', '{"es":"sentarse","fr":"s''asseoir","de":"sitzen","it":"sedersi","pt":"sentar","ja":"座る","zh":"坐","ko":"앉다","ar":"يجلس","ru":"сидеть"}', NULL, 'verb', 57),
('lose', '{"es":"perder","fr":"perdre","de":"verlieren","it":"perdere","pt":"perder","ja":"失う","zh":"失去","ko":"잃다","ar":"يخسر","ru":"терять"}', NULL, 'verb', 58),
('pay', '{"es":"pagar","fr":"payer","de":"bezahlen","it":"pagare","pt":"pagar","ja":"払う","zh":"付","ko":"지불하다","ar":"يدفع","ru":"платить"}', NULL, 'verb', 59),
('meet', '{"es":"conocer","fr":"rencontrer","de":"treffen","it":"incontrare","pt":"encontrar","ja":"会う","zh":"见面","ko":"만나다","ar":"يقابل","ru":"встречать"}', NULL, 'verb', 60),
('include', '{"es":"incluir","fr":"inclure","de":"einschließen","it":"includere","pt":"incluir","ja":"含む","zh":"包括","ko":"포함하다","ar":"يشمل","ru":"включать"}', NULL, 'verb', 61),
('continue', '{"es":"continuar","fr":"continuer","de":"fortsetzen","it":"continuare","pt":"continuar","ja":"続ける","zh":"继续","ko":"계속하다","ar":"يستمر","ru":"продолжать"}', NULL, 'verb', 62),
('set', '{"es":"establecer","fr":"établir","de":"setzen","it":"impostare","pt":"definir","ja":"設定する","zh":"设置","ko":"설정하다","ar":"يحدد","ru":"устанавливать"}', NULL, 'verb', 63),
('learn', '{"es":"aprender","fr":"apprendre","de":"lernen","it":"imparare","pt":"aprender","ja":"学ぶ","zh":"学习","ko":"배우다","ar":"يتعلم","ru":"учиться"}', NULL, 'verb', 64),
('change', '{"es":"cambiar","fr":"changer","de":"ändern","it":"cambiare","pt":"mudar","ja":"変える","zh":"改变","ko":"바꾸다","ar":"يغير","ru":"менять"}', NULL, 'verb', 65),
('watch', '{"es":"mirar","fr":"regarder","de":"schauen","it":"guardare","pt":"assistir","ja":"見る","zh":"观看","ko":"보다","ar":"يشاهد","ru":"смотреть"}', NULL, 'verb', 66),
('follow', '{"es":"seguir","fr":"suivre","de":"folgen","it":"seguire","pt":"seguir","ja":"従う","zh":"跟随","ko":"따르다","ar":"يتبع","ru":"следовать"}', NULL, 'verb', 67),
('stop', '{"es":"parar","fr":"arrêter","de":"stoppen","it":"fermare","pt":"parar","ja":"止める","zh":"停止","ko":"멈추다","ar":"يتوقف","ru":"останавливать"}', NULL, 'verb', 68),
('create', '{"es":"crear","fr":"créer","de":"erschaffen","it":"creare","pt":"criar","ja":"作成する","zh":"创造","ko":"만들다","ar":"يخلق","ru":"создавать"}', NULL, 'verb', 69),
('speak', '{"es":"hablar","fr":"parler","de":"sprechen","it":"parlare","pt":"falar","ja":"話す","zh":"说话","ko":"말하다","ar":"يتكلم","ru":"говорить"}', NULL, 'verb', 70),
('read', '{"es":"leer","fr":"lire","de":"lesen","it":"leggere","pt":"ler","ja":"読む","zh":"读","ko":"읽다","ar":"يقرأ","ru":"читать"}', NULL, 'verb', 71),
('spend', '{"es":"gastar","fr":"dépenser","de":"ausgeben","it":"spendere","pt":"gastar","ja":"費やす","zh":"花费","ko":"보내다","ar":"ينفق","ru":"тратить"}', NULL, 'verb', 72),
('grow', '{"es":"crecer","fr":"grandir","de":"wachsen","it":"crescere","pt":"crescer","ja":"成長する","zh":"成长","ko":"자라다","ar":"ينمو","ru":"расти"}', NULL, 'verb', 73),
('open', '{"es":"abrir","fr":"ouvrir","de":"öffnen","it":"aprire","pt":"abrir","ja":"開ける","zh":"打开","ko":"열다","ar":"يفتح","ru":"открывать"}', NULL, 'verb', 74),
('walk', '{"es":"caminar","fr":"marcher","de":"gehen","it":"camminare","pt":"andar","ja":"歩く","zh":"走","ko":"걷다","ar":"يمشي","ru":"ходить"}', NULL, 'verb', 75),
('win', '{"es":"ganar","fr":"gagner","de":"gewinnen","it":"vincere","pt":"ganhar","ja":"勝つ","zh":"赢","ko":"이기다","ar":"يفوز","ru":"выигрывать"}', NULL, 'verb', 76),
('teach', '{"es":"enseñar","fr":"enseigner","de":"unterrichten","it":"insegnare","pt":"ensinar","ja":"教える","zh":"教","ko":"가르치다","ar":"يعلم","ru":"учить"}', NULL, 'verb', 77),
('offer', '{"es":"ofrecer","fr":"offrir","de":"anbieten","it":"offrire","pt":"oferecer","ja":"提供する","zh":"提供","ko":"제공하다","ar":"يقدم","ru":"предлагать"}', NULL, 'verb', 78),
('remember', '{"es":"recordar","fr":"se souvenir","de":"sich erinnern","it":"ricordare","pt":"lembrar","ja":"覚えている","zh":"记得","ko":"기억하다","ar":"يتذكر","ru":"помнить"}', NULL, 'verb', 79),
('love', '{"es":"amar","fr":"aimer","de":"lieben","it":"amare","pt":"amar","ja":"愛する","zh":"爱","ko":"사랑하다","ar":"يحب","ru":"любить"}', '{"origin":"Old English","originalForm":"lufu","root":"*lubō","rootLanguage":"Proto-Germanic"}', 'verb', 80),
('eat', '{"es":"comer","fr":"manger","de":"essen","it":"mangiare","pt":"comer","ja":"食べる","zh":"吃","ko":"먹다","ar":"يأكل","ru":"есть"}', NULL, 'verb', 81),
('drink', '{"es":"beber","fr":"boire","de":"trinken","it":"bere","pt":"beber","ja":"飲む","zh":"喝","ko":"마시다","ar":"يشرب","ru":"пить"}', NULL, 'verb', 82),
('sleep', '{"es":"dormir","fr":"dormir","de":"schlafen","it":"dormire","pt":"dormir","ja":"眠る","zh":"睡觉","ko":"자다","ar":"ينام","ru":"спать"}', NULL, 'verb', 83),
('buy', '{"es":"comprar","fr":"acheter","de":"kaufen","it":"comprare","pt":"comprar","ja":"買う","zh":"买","ko":"사다","ar":"يشتري","ru":"покупать"}', NULL, 'verb', 84),
('sell', '{"es":"vender","fr":"vendre","de":"verkaufen","it":"vendere","pt":"vender","ja":"売る","zh":"卖","ko":"팔다","ar":"يبيع","ru":"продавать"}', NULL, 'verb', 85);

-- Common Nouns
INSERT OR IGNORE INTO dictionary_entries (word, translations_json, etymology_json, pos, frequency) VALUES
('time', '{"es":"tiempo","fr":"temps","de":"Zeit","it":"tempo","pt":"tempo","ja":"時間","zh":"时间","ko":"시간","ar":"وقت","ru":"время"}', NULL, 'noun', 86),
('year', '{"es":"año","fr":"année","de":"Jahr","it":"anno","pt":"ano","ja":"年","zh":"年","ko":"년","ar":"سنة","ru":"год"}', NULL, 'noun', 87),
('people', '{"es":"gente","fr":"gens","de":"Leute","it":"gente","pt":"pessoas","ja":"人々","zh":"人们","ko":"사람들","ar":"ناس","ru":"люди"}', NULL, 'noun', 88),
('way', '{"es":"manera","fr":"façon","de":"Weg","it":"modo","pt":"maneira","ja":"方法","zh":"方式","ko":"방법","ar":"طريقة","ru":"способ"}', NULL, 'noun', 89),
('day', '{"es":"día","fr":"jour","de":"Tag","it":"giorno","pt":"dia","ja":"日","zh":"天","ko":"날","ar":"يوم","ru":"день"}', NULL, 'noun', 90),
('man', '{"es":"hombre","fr":"homme","de":"Mann","it":"uomo","pt":"homem","ja":"男","zh":"男人","ko":"남자","ar":"رجل","ru":"мужчина"}', NULL, 'noun', 91),
('woman', '{"es":"mujer","fr":"femme","de":"Frau","it":"donna","pt":"mulher","ja":"女","zh":"女人","ko":"여자","ar":"امرأة","ru":"женщина"}', NULL, 'noun', 92),
('child', '{"es":"niño","fr":"enfant","de":"Kind","it":"bambino","pt":"criança","ja":"子供","zh":"孩子","ko":"아이","ar":"طفل","ru":"ребёнок"}', NULL, 'noun', 93),
('world', '{"es":"mundo","fr":"monde","de":"Welt","it":"mondo","pt":"mundo","ja":"世界","zh":"世界","ko":"세계","ar":"عالم","ru":"мир"}', NULL, 'noun', 94),
('life', '{"es":"vida","fr":"vie","de":"Leben","it":"vita","pt":"vida","ja":"人生","zh":"生活","ko":"인생","ar":"حياة","ru":"жизнь"}', NULL, 'noun', 95),
('hand', '{"es":"mano","fr":"main","de":"Hand","it":"mano","pt":"mão","ja":"手","zh":"手","ko":"손","ar":"يد","ru":"рука"}', NULL, 'noun', 96),
('part', '{"es":"parte","fr":"partie","de":"Teil","it":"parte","pt":"parte","ja":"部分","zh":"部分","ko":"부분","ar":"جزء","ru":"часть"}', NULL, 'noun', 97),
('place', '{"es":"lugar","fr":"lieu","de":"Ort","it":"posto","pt":"lugar","ja":"場所","zh":"地方","ko":"장소","ar":"مكان","ru":"место"}', NULL, 'noun', 98),
('case', '{"es":"caso","fr":"cas","de":"Fall","it":"caso","pt":"caso","ja":"場合","zh":"情况","ko":"경우","ar":"حالة","ru":"случай"}', NULL, 'noun', 99),
('week', '{"es":"semana","fr":"semaine","de":"Woche","it":"settimana","pt":"semana","ja":"週","zh":"周","ko":"주","ar":"أسبوع","ru":"неделя"}', NULL, 'noun', 100),
('company', '{"es":"empresa","fr":"entreprise","de":"Unternehmen","it":"azienda","pt":"empresa","ja":"会社","zh":"公司","ko":"회사","ar":"شركة","ru":"компания"}', NULL, 'noun', 101),
('system', '{"es":"sistema","fr":"système","de":"System","it":"sistema","pt":"sistema","ja":"システム","zh":"系统","ko":"시스템","ar":"نظام","ru":"система"}', NULL, 'noun', 102),
('program', '{"es":"programa","fr":"programme","de":"Programm","it":"programma","pt":"programa","ja":"プログラム","zh":"程序","ko":"프로그램","ar":"برنامج","ru":"программа"}', NULL, 'noun', 103),
('question', '{"es":"pregunta","fr":"question","de":"Frage","it":"domanda","pt":"pergunta","ja":"質問","zh":"问题","ko":"질문","ar":"سؤال","ru":"вопрос"}', NULL, 'noun', 104),
('labor', '{"es":"labor","fr":"travail","de":"Arbeit","it":"lavoro","pt":"labor","ja":"労働","zh":"劳动","ko":"노동","ar":"عمل","ru":"труд"}', NULL, 'noun', 105),
('government', '{"es":"gobierno","fr":"gouvernement","de":"Regierung","it":"governo","pt":"governo","ja":"政府","zh":"政府","ko":"정부","ar":"حكومة","ru":"правительство"}', NULL, 'noun', 106),
('number', '{"es":"número","fr":"numéro","de":"Nummer","it":"numero","pt":"número","ja":"番号","zh":"号码","ko":"번호","ar":"رقم","ru":"номер"}', NULL, 'noun', 107),
('night', '{"es":"noche","fr":"nuit","de":"Nacht","it":"notte","pt":"noite","ja":"夜","zh":"夜晚","ko":"밤","ar":"ليل","ru":"ночь"}', NULL, 'noun', 108),
('point', '{"es":"punto","fr":"point","de":"Punkt","it":"punto","pt":"ponto","ja":"点","zh":"点","ko":"점","ar":"نقطة","ru":"точка"}', NULL, 'noun', 109),
('home', '{"es":"casa","fr":"maison","de":"Haus","it":"casa","pt":"casa","ja":"家","zh":"家","ko":"집","ar":"منزل","ru":"дом"}', NULL, 'noun', 110),
('water', '{"es":"agua","fr":"eau","de":"Wasser","it":"acqua","pt":"água","ja":"水","zh":"水","ko":"물","ar":"ماء","ru":"вода"}', '{"origin":"Old English","originalForm":"wæter","root":"*wódr̥","rootLanguage":"Proto-Indo-European"}', 'noun', 111),
('room', '{"es":"habitación","fr":"chambre","de":"Zimmer","it":"stanza","pt":"quarto","ja":"部屋","zh":"房间","ko":"방","ar":"غرفة","ru":"комната"}', NULL, 'noun', 112),
('mother', '{"es":"madre","fr":"mère","de":"Mutter","it":"madre","pt":"mãe","ja":"母","zh":"母亲","ko":"어머니","ar":"أم","ru":"мать"}', '{"origin":"Old English","originalForm":"mōdor","root":"*méh₂tēr","rootLanguage":"Proto-Indo-European"}', 'noun', 113),
('father', '{"es":"padre","fr":"père","de":"Vater","it":"padre","pt":"pai","ja":"父","zh":"父亲","ko":"아버지","ar":"أب","ru":"отец"}', '{"origin":"Old English","originalForm":"fæder","root":"*ph₂tḗr","rootLanguage":"Proto-Indo-European"}', 'noun', 114),
('area', '{"es":"área","fr":"zone","de":"Bereich","it":"area","pt":"área","ja":"エリア","zh":"地区","ko":"지역","ar":"منطقة","ru":"область"}', NULL, 'noun', 115),
('money', '{"es":"dinero","fr":"argent","de":"Geld","it":"soldi","pt":"dinheiro","ja":"お金","zh":"钱","ko":"돈","ar":"مال","ru":"деньги"}', NULL, 'noun', 116),
('story', '{"es":"historia","fr":"histoire","de":"Geschichte","it":"storia","pt":"história","ja":"物語","zh":"故事","ko":"이야기","ar":"قصة","ru":"история"}', NULL, 'noun', 117),
('fact', '{"es":"hecho","fr":"fait","de":"Tatsache","it":"fatto","pt":"fato","ja":"事実","zh":"事实","ko":"사실","ar":"حقيقة","ru":"факт"}', NULL, 'noun', 118),
('month', '{"es":"mes","fr":"mois","de":"Monat","it":"mese","pt":"mês","ja":"月","zh":"月","ko":"달","ar":"شهر","ru":"месяц"}', NULL, 'noun', 119),
('lot', '{"es":"mucho","fr":"beaucoup","de":"viel","it":"molto","pt":"muito","ja":"たくさん","zh":"很多","ko":"많이","ar":"كثير","ru":"много"}', NULL, 'noun', 120),
('right', '{"es":"derecho","fr":"droit","de":"Recht","it":"diritto","pt":"direito","ja":"権利","zh":"权利","ko":"권리","ar":"حق","ru":"право"}', NULL, 'noun', 121),
('study', '{"es":"estudio","fr":"étude","de":"Studie","it":"studio","pt":"estudo","ja":"研究","zh":"研究","ko":"연구","ar":"دراسة","ru":"исследование"}', NULL, 'noun', 122),
('book', '{"es":"libro","fr":"livre","de":"Buch","it":"libro","pt":"livro","ja":"本","zh":"书","ko":"책","ar":"كتاب","ru":"книга"}', NULL, 'noun', 123),
('eye', '{"es":"ojo","fr":"œil","de":"Auge","it":"occhio","pt":"olho","ja":"目","zh":"眼睛","ko":"눈","ar":"عين","ru":"глаз"}', NULL, 'noun', 124),
('job', '{"es":"trabajo","fr":"emploi","de":"Job","it":"lavoro","pt":"emprego","ja":"仕事","zh":"工作","ko":"직업","ar":"وظيفة","ru":"работа"}', NULL, 'noun', 125),
('word', '{"es":"palabra","fr":"mot","de":"Wort","it":"parola","pt":"palavra","ja":"言葉","zh":"词","ko":"단어","ar":"كلمة","ru":"слово"}', NULL, 'noun', 126),
('business', '{"es":"negocio","fr":"affaires","de":"Geschäft","it":"affari","pt":"negócio","ja":"ビジネス","zh":"商业","ko":"비즈니스","ar":"عمل","ru":"бизнес"}', NULL, 'noun', 127),
('issue', '{"es":"asunto","fr":"problème","de":"Problem","it":"problema","pt":"questão","ja":"問題","zh":"问题","ko":"문제","ar":"مسألة","ru":"вопрос"}', NULL, 'noun', 128),
('side', '{"es":"lado","fr":"côté","de":"Seite","it":"lato","pt":"lado","ja":"側","zh":"边","ko":"측면","ar":"جانب","ru":"сторона"}', NULL, 'noun', 129),
('kind', '{"es":"tipo","fr":"genre","de":"Art","it":"tipo","pt":"tipo","ja":"種類","zh":"种类","ko":"종류","ar":"نوع","ru":"вид"}', NULL, 'noun', 130),
('head', '{"es":"cabeza","fr":"tête","de":"Kopf","it":"testa","pt":"cabeça","ja":"頭","zh":"头","ko":"머리","ar":"رأس","ru":"голова"}', NULL, 'noun', 131),
('house', '{"es":"casa","fr":"maison","de":"Haus","it":"casa","pt":"casa","ja":"家","zh":"房子","ko":"집","ar":"منزل","ru":"дом"}', NULL, 'noun', 132),
('friend', '{"es":"amigo","fr":"ami","de":"Freund","it":"amico","pt":"amigo","ja":"友達","zh":"朋友","ko":"친구","ar":"صديق","ru":"друг"}', NULL, 'noun', 133),
('school', '{"es":"escuela","fr":"école","de":"Schule","it":"scuola","pt":"escola","ja":"学校","zh":"学校","ko":"학교","ar":"مدرسة","ru":"школа"}', NULL, 'noun', 134),
('country', '{"es":"país","fr":"pays","de":"Land","it":"paese","pt":"país","ja":"国","zh":"国家","ko":"나라","ar":"بلد","ru":"страна"}', NULL, 'noun', 135),
('problem', '{"es":"problema","fr":"problème","de":"Problem","it":"problema","pt":"problema","ja":"問題","zh":"问题","ko":"문제","ar":"مشكلة","ru":"проблема"}', NULL, 'noun', 136),
('state', '{"es":"estado","fr":"état","de":"Staat","it":"stato","pt":"estado","ja":"状態","zh":"状态","ko":"상태","ar":"حالة","ru":"состояние"}', NULL, 'noun', 137),
('group', '{"es":"grupo","fr":"groupe","de":"Gruppe","it":"gruppo","pt":"grupo","ja":"グループ","zh":"组","ko":"그룹","ar":"مجموعة","ru":"группа"}', NULL, 'noun', 138),
('member', '{"es":"miembro","fr":"membre","de":"Mitglied","it":"membro","pt":"membro","ja":"メンバー","zh":"成员","ko":"회원","ar":"عضو","ru":"член"}', NULL, 'noun', 139),
('family', '{"es":"familia","fr":"famille","de":"Familie","it":"famiglia","pt":"família","ja":"家族","zh":"家庭","ko":"가족","ar":"عائلة","ru":"семья"}', NULL, 'noun', 140),
('power', '{"es":"poder","fr":"pouvoir","de":"Macht","it":"potere","pt":"poder","ja":"力","zh":"力量","ko":"힘","ar":"قوة","ru":"сила"}', NULL, 'noun', 141),
('body', '{"es":"cuerpo","fr":"corps","de":"Körper","it":"corpo","pt":"corpo","ja":"体","zh":"身体","ko":"몸","ar":"جسم","ru":"тело"}', NULL, 'noun', 142),
('food', '{"es":"comida","fr":"nourriture","de":"Essen","it":"cibo","pt":"comida","ja":"食べ物","zh":"食物","ko":"음식","ar":"طعام","ru":"еда"}', NULL, 'noun', 143),
('car', '{"es":"coche","fr":"voiture","de":"Auto","it":"macchina","pt":"carro","ja":"車","zh":"汽车","ko":"차","ar":"سيارة","ru":"машина"}', NULL, 'noun', 144),
('city', '{"es":"ciudad","fr":"ville","de":"Stadt","it":"città","pt":"cidade","ja":"都市","zh":"城市","ko":"도시","ar":"مدينة","ru":"город"}', NULL, 'noun', 145);

-- Common Adjectives
INSERT OR IGNORE INTO dictionary_entries (word, translations_json, etymology_json, pos, frequency) VALUES
('good', '{"es":"bueno","fr":"bon","de":"gut","it":"buono","pt":"bom","ja":"良い","zh":"好","ko":"좋은","ar":"جيد","ru":"хороший"}', NULL, 'adjective', 146),
('new', '{"es":"nuevo","fr":"nouveau","de":"neu","it":"nuovo","pt":"novo","ja":"新しい","zh":"新","ko":"새로운","ar":"جديد","ru":"новый"}', NULL, 'adjective', 147),
('first', '{"es":"primero","fr":"premier","de":"erste","it":"primo","pt":"primeiro","ja":"最初の","zh":"第一","ko":"첫 번째","ar":"أول","ru":"первый"}', NULL, 'adjective', 148),
('last', '{"es":"último","fr":"dernier","de":"letzte","it":"ultimo","pt":"último","ja":"最後の","zh":"最后","ko":"마지막","ar":"آخر","ru":"последний"}', NULL, 'adjective', 149),
('long', '{"es":"largo","fr":"long","de":"lang","it":"lungo","pt":"longo","ja":"長い","zh":"长","ko":"긴","ar":"طويل","ru":"длинный"}', NULL, 'adjective', 150),
('great', '{"es":"gran","fr":"grand","de":"groß","it":"grande","pt":"grande","ja":"素晴らしい","zh":"伟大","ko":"위대한","ar":"عظيم","ru":"великий"}', NULL, 'adjective', 151),
('little', '{"es":"pequeño","fr":"petit","de":"klein","it":"piccolo","pt":"pequeno","ja":"小さい","zh":"小","ko":"작은","ar":"صغير","ru":"маленький"}', NULL, 'adjective', 152),
('own', '{"es":"propio","fr":"propre","de":"eigen","it":"proprio","pt":"próprio","ja":"自分の","zh":"自己的","ko":"자신의","ar":"خاص","ru":"собственный"}', NULL, 'adjective', 153),
('other', '{"es":"otro","fr":"autre","de":"andere","it":"altro","pt":"outro","ja":"他の","zh":"其他","ko":"다른","ar":"آخر","ru":"другой"}', NULL, 'adjective', 154),
('old', '{"es":"viejo","fr":"vieux","de":"alt","it":"vecchio","pt":"velho","ja":"古い","zh":"老","ko":"오래된","ar":"قديم","ru":"старый"}', NULL, 'adjective', 155),
('right', '{"es":"correcto","fr":"correct","de":"richtig","it":"giusto","pt":"certo","ja":"正しい","zh":"对","ko":"옳은","ar":"صحيح","ru":"правильный"}', NULL, 'adjective', 156),
('big', '{"es":"grande","fr":"grand","de":"groß","it":"grande","pt":"grande","ja":"大きい","zh":"大","ko":"큰","ar":"كبير","ru":"большой"}', NULL, 'adjective', 157),
('high', '{"es":"alto","fr":"haut","de":"hoch","it":"alto","pt":"alto","ja":"高い","zh":"高","ko":"높은","ar":"عالي","ru":"высокий"}', NULL, 'adjective', 158),
('different', '{"es":"diferente","fr":"différent","de":"verschieden","it":"diverso","pt":"diferente","ja":"違う","zh":"不同","ko":"다른","ar":"مختلف","ru":"разный"}', NULL, 'adjective', 159),
('small', '{"es":"pequeño","fr":"petit","de":"klein","it":"piccolo","pt":"pequeno","ja":"小さい","zh":"小","ko":"작은","ar":"صغير","ru":"маленький"}', NULL, 'adjective', 160),
('large', '{"es":"grande","fr":"grand","de":"groß","it":"grande","pt":"grande","ja":"大きい","zh":"大","ko":"큰","ar":"كبير","ru":"большой"}', NULL, 'adjective', 161),
('important', '{"es":"importante","fr":"important","de":"wichtig","it":"importante","pt":"importante","ja":"重要な","zh":"重要","ko":"중요한","ar":"مهم","ru":"важный"}', NULL, 'adjective', 162),
('young', '{"es":"joven","fr":"jeune","de":"jung","it":"giovane","pt":"jovem","ja":"若い","zh":"年轻","ko":"젊은","ar":"شاب","ru":"молодой"}', NULL, 'adjective', 163),
('national', '{"es":"nacional","fr":"national","de":"national","it":"nazionale","pt":"nacional","ja":"国の","zh":"国家的","ko":"국가의","ar":"وطني","ru":"национальный"}', NULL, 'adjective', 164),
('possible', '{"es":"posible","fr":"possible","de":"möglich","it":"possibile","pt":"possível","ja":"可能な","zh":"可能","ko":"가능한","ar":"ممكن","ru":"возможный"}', NULL, 'adjective', 165),
('bad', '{"es":"malo","fr":"mauvais","de":"schlecht","it":"cattivo","pt":"mau","ja":"悪い","zh":"坏","ko":"나쁜","ar":"سيء","ru":"плохой"}', NULL, 'adjective', 166),
('true', '{"es":"verdadero","fr":"vrai","de":"wahr","it":"vero","pt":"verdadeiro","ja":"本当の","zh":"真","ko":"진짜의","ar":"صحيح","ru":"правдивый"}', NULL, 'adjective', 167),
('able', '{"es":"capaz","fr":"capable","de":"fähig","it":"capace","pt":"capaz","ja":"できる","zh":"能够","ko":"할 수 있는","ar":"قادر","ru":"способный"}', NULL, 'adjective', 168),
('free', '{"es":"libre","fr":"libre","de":"frei","it":"libero","pt":"livre","ja":"自由な","zh":"免费","ko":"자유로운","ar":"حر","ru":"свободный"}', NULL, 'adjective', 169),
('hard', '{"es":"difícil","fr":"difficile","de":"schwer","it":"difficile","pt":"difícil","ja":"難しい","zh":"难","ko":"어려운","ar":"صعب","ru":"трудный"}', NULL, 'adjective', 170),
('easy', '{"es":"fácil","fr":"facile","de":"einfach","it":"facile","pt":"fácil","ja":"簡単な","zh":"容易","ko":"쉬운","ar":"سهل","ru":"лёгкий"}', NULL, 'adjective', 171),
('happy', '{"es":"feliz","fr":"heureux","de":"glücklich","it":"felice","pt":"feliz","ja":"幸せな","zh":"快乐","ko":"행복한","ar":"سعيد","ru":"счастливый"}', NULL, 'adjective', 172),
('sad', '{"es":"triste","fr":"triste","de":"traurig","it":"triste","pt":"triste","ja":"悲しい","zh":"悲伤","ko":"슬픈","ar":"حزين","ru":"грустный"}', NULL, 'adjective', 173),
('beautiful', '{"es":"hermoso","fr":"beau","de":"schön","it":"bello","pt":"bonito","ja":"美しい","zh":"美丽","ko":"아름다운","ar":"جميل","ru":"красивый"}', NULL, 'adjective', 174),
('fast', '{"es":"rápido","fr":"rapide","de":"schnell","it":"veloce","pt":"rápido","ja":"速い","zh":"快","ko":"빠른","ar":"سريع","ru":"быстрый"}', NULL, 'adjective', 175),
('slow', '{"es":"lento","fr":"lent","de":"langsam","it":"lento","pt":"lento","ja":"遅い","zh":"慢","ko":"느린","ar":"بطيء","ru":"медленный"}', NULL, 'adjective', 176),
('hot', '{"es":"caliente","fr":"chaud","de":"heiß","it":"caldo","pt":"quente","ja":"熱い","zh":"热","ko":"뜨거운","ar":"حار","ru":"горячий"}', NULL, 'adjective', 177),
('cold', '{"es":"frío","fr":"froid","de":"kalt","it":"freddo","pt":"frio","ja":"寒い","zh":"冷","ko":"차가운","ar":"بارد","ru":"холодный"}', NULL, 'adjective', 178),
('dark', '{"es":"oscuro","fr":"sombre","de":"dunkel","it":"scuro","pt":"escuro","ja":"暗い","zh":"黑暗","ko":"어두운","ar":"مظلم","ru":"тёмный"}', NULL, 'adjective', 179),
('light', '{"es":"ligero","fr":"léger","de":"leicht","it":"leggero","pt":"leve","ja":"軽い","zh":"轻","ko":"가벼운","ar":"خفيف","ru":"лёгкий"}', NULL, 'adjective', 180);

-- Common Adverbs & Prepositions
INSERT OR IGNORE INTO dictionary_entries (word, translations_json, etymology_json, pos, frequency) VALUES
('also', '{"es":"también","fr":"aussi","de":"auch","it":"anche","pt":"também","ja":"また","zh":"也","ko":"또한","ar":"أيضا","ru":"тоже"}', NULL, 'adverb', 181),
('when', '{"es":"cuándo","fr":"quand","de":"wann","it":"quando","pt":"quando","ja":"いつ","zh":"什么时候","ko":"언제","ar":"متى","ru":"когда"}', NULL, 'adverb', 182),
('there', '{"es":"allí","fr":"là","de":"dort","it":"là","pt":"lá","ja":"そこ","zh":"那里","ko":"거기","ar":"هناك","ru":"там"}', NULL, 'adverb', 183),
('here', '{"es":"aquí","fr":"ici","de":"hier","it":"qui","pt":"aqui","ja":"ここ","zh":"这里","ko":"여기","ar":"هنا","ru":"здесь"}', NULL, 'adverb', 184),
('now', '{"es":"ahora","fr":"maintenant","de":"jetzt","it":"ora","pt":"agora","ja":"今","zh":"现在","ko":"지금","ar":"الآن","ru":"сейчас"}', NULL, 'adverb', 185),
('then', '{"es":"entonces","fr":"alors","de":"dann","it":"allora","pt":"então","ja":"それから","zh":"然后","ko":"그때","ar":"ثم","ru":"тогда"}', NULL, 'adverb', 186),
('always', '{"es":"siempre","fr":"toujours","de":"immer","it":"sempre","pt":"sempre","ja":"いつも","zh":"总是","ko":"항상","ar":"دائما","ru":"всегда"}', NULL, 'adverb', 187),
('never', '{"es":"nunca","fr":"jamais","de":"nie","it":"mai","pt":"nunca","ja":"決して","zh":"从不","ko":"결코","ar":"أبدا","ru":"никогда"}', NULL, 'adverb', 188),
('often', '{"es":"a menudo","fr":"souvent","de":"oft","it":"spesso","pt":"frequentemente","ja":"よく","zh":"经常","ko":"자주","ar":"غالبا","ru":"часто"}', NULL, 'adverb', 189),
('sometimes', '{"es":"a veces","fr":"parfois","de":"manchmal","it":"a volte","pt":"às vezes","ja":"時々","zh":"有时","ko":"때때로","ar":"أحيانا","ru":"иногда"}', NULL, 'adverb', 190),
('today', '{"es":"hoy","fr":"aujourd''hui","de":"heute","it":"oggi","pt":"hoje","ja":"今日","zh":"今天","ko":"오늘","ar":"اليوم","ru":"сегодня"}', NULL, 'adverb', 191),
('tomorrow', '{"es":"mañana","fr":"demain","de":"morgen","it":"domani","pt":"amanhã","ja":"明日","zh":"明天","ko":"내일","ar":"غدا","ru":"завтра"}', NULL, 'adverb', 192),
('yesterday', '{"es":"ayer","fr":"hier","de":"gestern","it":"ieri","pt":"ontem","ja":"昨日","zh":"昨天","ko":"어제","ar":"أمس","ru":"вчера"}', NULL, 'adverb', 193),
('with', '{"es":"con","fr":"avec","de":"mit","it":"con","pt":"com","ja":"と","zh":"和","ko":"와/과","ar":"مع","ru":"с"}', NULL, 'preposition', 194),
('without', '{"es":"sin","fr":"sans","de":"ohne","it":"senza","pt":"sem","ja":"なしで","zh":"没有","ko":"없이","ar":"بدون","ru":"без"}', NULL, 'preposition', 195),
('from', '{"es":"de","fr":"de","de":"von","it":"da","pt":"de","ja":"から","zh":"从","ko":"에서","ar":"من","ru":"из"}', NULL, 'preposition', 196),
('to', '{"es":"a","fr":"à","de":"zu","it":"a","pt":"para","ja":"へ","zh":"到","ko":"에","ar":"إلى","ru":"к"}', NULL, 'preposition', 197),
('in', '{"es":"en","fr":"dans","de":"in","it":"in","pt":"em","ja":"中","zh":"在","ko":"안에","ar":"في","ru":"в"}', NULL, 'preposition', 198),
('on', '{"es":"sobre","fr":"sur","de":"auf","it":"su","pt":"sobre","ja":"上に","zh":"上","ko":"위에","ar":"على","ru":"на"}', NULL, 'preposition', 199),
('between', '{"es":"entre","fr":"entre","de":"zwischen","it":"tra","pt":"entre","ja":"間","zh":"之间","ko":"사이에","ar":"بين","ru":"между"}', NULL, 'preposition', 200);

-- Colors
INSERT OR IGNORE INTO dictionary_entries (word, translations_json, etymology_json, pos, frequency) VALUES
('red', '{"es":"rojo","fr":"rouge","de":"rot","it":"rosso","pt":"vermelho","ja":"赤","zh":"红","ko":"빨간","ar":"أحمر","ru":"красный"}', NULL, 'adjective', 201),
('blue', '{"es":"azul","fr":"bleu","de":"blau","it":"blu","pt":"azul","ja":"青","zh":"蓝","ko":"파란","ar":"أزرق","ru":"синий"}', NULL, 'adjective', 202),
('green', '{"es":"verde","fr":"vert","de":"grün","it":"verde","pt":"verde","ja":"緑","zh":"绿","ko":"초록","ar":"أخضر","ru":"зелёный"}', NULL, 'adjective', 203),
('yellow', '{"es":"amarillo","fr":"jaune","de":"gelb","it":"giallo","pt":"amarelo","ja":"黄色","zh":"黄","ko":"노란","ar":"أصفر","ru":"жёлтый"}', NULL, 'adjective', 204),
('black', '{"es":"negro","fr":"noir","de":"schwarz","it":"nero","pt":"preto","ja":"黒","zh":"黑","ko":"검은","ar":"أسود","ru":"чёрный"}', NULL, 'adjective', 205),
('white', '{"es":"blanco","fr":"blanc","de":"weiß","it":"bianco","pt":"branco","ja":"白","zh":"白","ko":"흰","ar":"أبيض","ru":"белый"}', NULL, 'adjective', 206),
('orange', '{"es":"naranja","fr":"orange","de":"orange","it":"arancione","pt":"laranja","ja":"オレンジ","zh":"橙","ko":"주황","ar":"برتقالي","ru":"оранжевый"}', NULL, 'adjective', 207),
('purple', '{"es":"morado","fr":"violet","de":"lila","it":"viola","pt":"roxo","ja":"紫","zh":"紫","ko":"보라","ar":"بنفسجي","ru":"фиолетовый"}', NULL, 'adjective', 208),
('pink', '{"es":"rosa","fr":"rose","de":"rosa","it":"rosa","pt":"rosa","ja":"ピンク","zh":"粉红","ko":"분홍","ar":"وردي","ru":"розовый"}', NULL, 'adjective', 209),
('brown', '{"es":"marrón","fr":"marron","de":"braun","it":"marrone","pt":"marrom","ja":"茶色","zh":"棕","ko":"갈색","ar":"بني","ru":"коричневый"}', NULL, 'adjective', 210),
('gray', '{"es":"gris","fr":"gris","de":"grau","it":"grigio","pt":"cinza","ja":"灰色","zh":"灰","ko":"회색","ar":"رمادي","ru":"серый"}', NULL, 'adjective', 211);

-- Numbers as Words
INSERT OR IGNORE INTO dictionary_entries (word, translations_json, etymology_json, pos, frequency) VALUES
('one', '{"es":"uno","fr":"un","de":"eins","it":"uno","pt":"um","ja":"一","zh":"一","ko":"하나","ar":"واحد","ru":"один"}', NULL, 'number', 212),
('two', '{"es":"dos","fr":"deux","de":"zwei","it":"due","pt":"dois","ja":"二","zh":"二","ko":"둘","ar":"اثنان","ru":"два"}', NULL, 'number', 213),
('three', '{"es":"tres","fr":"trois","de":"drei","it":"tre","pt":"três","ja":"三","zh":"三","ko":"셋","ar":"ثلاثة","ru":"три"}', NULL, 'number', 214),
('four', '{"es":"cuatro","fr":"quatre","de":"vier","it":"quattro","pt":"quatro","ja":"四","zh":"四","ko":"넷","ar":"أربعة","ru":"четыре"}', NULL, 'number', 215),
('five', '{"es":"cinco","fr":"cinq","de":"fünf","it":"cinque","pt":"cinco","ja":"五","zh":"五","ko":"다섯","ar":"خمسة","ru":"пять"}', NULL, 'number', 216),
('six', '{"es":"seis","fr":"six","de":"sechs","it":"sei","pt":"seis","ja":"六","zh":"六","ko":"여섯","ar":"ستة","ru":"шесть"}', NULL, 'number', 217),
('seven', '{"es":"siete","fr":"sept","de":"sieben","it":"sette","pt":"sete","ja":"七","zh":"七","ko":"일곱","ar":"سبعة","ru":"семь"}', NULL, 'number', 218),
('eight', '{"es":"ocho","fr":"huit","de":"acht","it":"otto","pt":"oito","ja":"八","zh":"八","ko":"여덟","ar":"ثمانية","ru":"восемь"}', NULL, 'number', 219),
('nine', '{"es":"nueve","fr":"neuf","de":"neun","it":"nove","pt":"nove","ja":"九","zh":"九","ko":"아홉","ar":"تسعة","ru":"девять"}', NULL, 'number', 220),
('ten', '{"es":"diez","fr":"dix","de":"zehn","it":"dieci","pt":"dez","ja":"十","zh":"十","ko":"열","ar":"عشرة","ru":"десять"}', NULL, 'number', 221),
('hundred', '{"es":"cien","fr":"cent","de":"hundert","it":"cento","pt":"cem","ja":"百","zh":"百","ko":"백","ar":"مائة","ru":"сто"}', NULL, 'number', 222),
('thousand', '{"es":"mil","fr":"mille","de":"tausend","it":"mille","pt":"mil","ja":"千","zh":"千","ko":"천","ar":"ألف","ru":"тысяча"}', NULL, 'number', 223),
('million', '{"es":"millón","fr":"million","de":"Million","it":"milione","pt":"milhão","ja":"百万","zh":"百万","ko":"백만","ar":"مليون","ru":"миллион"}', NULL, 'number', 224);

-- More Common Verbs
INSERT OR IGNORE INTO dictionary_entries (word, translations_json, etymology_json, pos, frequency) VALUES
('ask', '{"es":"preguntar","fr":"demander","de":"fragen","it":"chiedere","pt":"perguntar","ja":"聞く","zh":"问","ko":"묻다","ar":"يسأل","ru":"спрашивать"}', NULL, 'verb', 225),
('answer', '{"es":"responder","fr":"répondre","de":"antworten","it":"rispondere","pt":"responder","ja":"答える","zh":"回答","ko":"대답하다","ar":"يجيب","ru":"отвечать"}', NULL, 'verb', 226),
('close', '{"es":"cerrar","fr":"fermer","de":"schließen","it":"chiudere","pt":"fechar","ja":"閉める","zh":"关闭","ko":"닫다","ar":"يغلق","ru":"закрывать"}', NULL, 'verb', 227),
('wait', '{"es":"esperar","fr":"attendre","de":"warten","it":"aspettare","pt":"esperar","ja":"待つ","zh":"等","ko":"기다리다","ar":"ينتظر","ru":"ждать"}', NULL, 'verb', 228),
('start', '{"es":"empezar","fr":"commencer","de":"anfangen","it":"iniziare","pt":"começar","ja":"始める","zh":"开始","ko":"시작하다","ar":"يبدأ","ru":"начинать"}', NULL, 'verb', 229),
('finish', '{"es":"terminar","fr":"finir","de":"beenden","it":"finire","pt":"terminar","ja":"終える","zh":"完成","ko":"끝내다","ar":"ينهي","ru":"заканчивать"}', NULL, 'verb', 230);
