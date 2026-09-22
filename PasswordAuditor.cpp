// ============================================================================
//  Password Strength Auditor
//  Design & Technology - AI Windows Application Sprint Challenge
//
//  Native C++ / Win32 desktop application. No .NET, no MFC, no Qt,
//  no external libraries. Unicode from the outset.
//
//  Build: Visual Studio -> Windows Desktop Application (C++)
//         Character Set = Use Unicode Character Set
//         Linker -> System -> SubSystem = Windows (/SUBSYSTEM:WINDOWS)
// ============================================================================

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <string>
#include <vector>
#include <sstream>
#include <cmath>
#include <cwctype>
#include <cstdlib>
#include <random>
#include <algorithm>

// ---------------------------------------------------------------------------
// Control identifiers
// ---------------------------------------------------------------------------
#define IDC_PASSWORD_EDIT   101
#define IDC_SHOW_CHECK      102
#define IDC_ANALYSE_BTN     103
#define IDC_GENERATE_BTN    104
#define IDC_CLEAR_BTN       105
#define IDC_OUTPUT_EDIT     106
#define IDC_SCORE_LABEL     107

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------
static HWND     gMainWnd        = NULL;
static HWND     gPasswordEdit   = NULL;
static HWND     gShowCheck      = NULL;
static HWND     gOutputEdit     = NULL;
static HWND     gScoreLabel     = NULL;
static HFONT    gUiFont         = NULL;
static HFONT    gTitleFont      = NULL;
static HFONT    gScoreFont      = NULL;
static HFONT    gMonoFont       = NULL;
static COLORREF gScoreColour    = RGB(70, 70, 70);

// ---------------------------------------------------------------------------
// Result of an audit
// ---------------------------------------------------------------------------
struct AuditResult
{
    int                       length;
    int                       poolSize;
    double                    rawEntropy;      // bits, before penalties
    double                    effectiveEntropy;// bits, after penalties
    int                       score;           // 0 - 100
    std::wstring              rating;
    std::wstring              crackTime;
    COLORREF                  colour;
    std::vector<std::wstring> strengths;
    std::vector<std::wstring> issues;
    std::vector<std::wstring> recommendations;
    std::wstring              improvementNote;
};

// ---------------------------------------------------------------------------
// Word lists
// ---------------------------------------------------------------------------

// Passwords that appear at the very top of every leaked-password list.
static const wchar_t* kCommonPasswords[] = {
    L"123456", L"password", L"12345678", L"qwerty", L"123456789", L"12345",
    L"1234", L"111111", L"1234567", L"dragon", L"123123", L"baseball",
    L"abc123", L"football", L"monkey", L"letmein", L"696969", L"shadow",
    L"master", L"666666", L"qwertyuiop", L"123321", L"mustang", L"1234567890",
    L"michael", L"654321", L"superman", L"1qaz2wsx", L"7777777", L"121212",
    L"000000", L"qazwsx", L"123qwe", L"killer", L"trustno1", L"jordan",
    L"jennifer", L"zxcvbnm", L"asdfgh", L"hunter", L"buster", L"soccer",
    L"harley", L"batman", L"andrew", L"tigger", L"sunshine", L"iloveyou",
    L"charlie", L"robert", L"thomas", L"hockey", L"ranger", L"daniel",
    L"starwars", L"klaster", L"112233", L"george", L"computer", L"michelle",
    L"jessica", L"pepper", L"1111", L"zxcvbn", L"555555", L"11111111",
    L"131313", L"freedom", L"777777", L"pass", L"maggie", L"159753",
    L"aaaaaa", L"ginger", L"princess", L"joshua", L"cheese", L"amanda",
    L"summer", L"love", L"ashley", L"nicole", L"chelsea", L"biteme",
    L"matthew", L"access", L"yankees", L"987654321", L"dallas", L"austin",
    L"thunder", L"taylor", L"matrix", L"welcome", L"admin", L"login",
    L"passw0rd", L"p@ssword", L"p@ssw0rd", L"password1", L"password123",
    L"qwerty123", L"abcd1234", L"iloveyou1", L"letmein1", L"changeme"
};

// Common English words used inside passwords. Detected as predictable chunks.
static const wchar_t* kDictionaryWords[] = {
    L"password", L"admin", L"login", L"user", L"welcome", L"secret", L"love",
    L"hello", L"money", L"school", L"student", L"teacher", L"gaming", L"gamer",
    L"minecraft", L"fortnite", L"roblox", L"computer", L"laptop", L"phone",
    L"music", L"guitar", L"drums", L"piano", L"football", L"soccer", L"cricket",
    L"netball", L"basketball", L"hockey", L"tennis", L"swimming", L"surfing",
    L"skating", L"running", L"dragon", L"monkey", L"tiger", L"eagle", L"shark",
    L"wolf", L"dog", L"cat", L"horse", L"summer", L"winter", L"spring",
    L"autumn", L"january", L"february", L"march", L"april", L"june", L"july",
    L"august", L"september", L"october", L"november", L"december", L"monday",
    L"tuesday", L"wednesday", L"thursday", L"friday", L"saturday", L"sunday",
    L"mother", L"father", L"sister", L"brother", L"family", L"friend", L"home",
    L"house", L"school", L"perth", L"sydney", L"melbourne", L"brisbane",
    L"australia", L"apple", L"google", L"samsung", L"windows", L"xbox",
    L"playstation", L"nintendo", L"chocolate", L"pizza", L"coffee", L"cookie",
    L"sunshine", L"rainbow", L"angel", L"devil", L"ninja", L"master", L"super",
    L"star", L"moon", L"blue", L"black", L"green", L"white", L"red", L"silver",
    L"gold", L"king", L"queen", L"prince", L"princess", L"batman", L"superman",
    L"spiderman", L"marvel", L"soccer", L"legend", L"champion", L"winner"
};

// Runs across a QWERTY keyboard. Looks random, is not.
static const wchar_t* kKeyboardRuns[] = {
    L"qwerty", L"qwertz", L"asdfgh", L"zxcvbn", L"qwer", L"asdf", L"zxcv",
    L"wasd", L"1qaz", L"2wsx", L"3edc", L"4rfv", L"qazwsx", L"poiuy",
    L"lkjh", L"mnbv", L"yuiop", L"hjkl", L"vbnm", L"qwertyuiop", L"asdfghjkl",
    L"zxcvbnm", L"1q2w3e", L"a1b2c3"
};

// Words used to build generated passphrases. Short, concrete, easy to recall.
static const wchar_t* kPassphraseWords[] = {
    L"anchor", L"bamboo", L"basket", L"beacon", L"bicycle", L"bridge",
    L"bucket", L"cactus", L"candle", L"canyon", L"carbon", L"cavern",
    L"cinder", L"clover", L"compass", L"copper", L"coral", L"crater",
    L"crimson", L"crystal", L"dagger", L"desert", L"diamond", L"dolphin",
    L"ember", L"engine", L"falcon", L"feather", L"fossil", L"galaxy",
    L"garden", L"glacier", L"granite", L"gravel", L"harbour", L"hollow",
    L"hunter", L"iceberg", L"island", L"jacket", L"jungle", L"kettle",
    L"lantern", L"lasso", L"lemon", L"lizard", L"magnet", L"marble",
    L"meadow", L"meteor", L"mirror", L"mosaic", L"nebula", L"needle",
    L"nickel", L"orbit", L"otter", L"oxide", L"paddle", L"pebble",
    L"pepper", L"pillar", L"pigeon", L"planet", L"pocket", L"prism",
    L"quartz", L"quiver", L"rabbit", L"rattle", L"ribbon", L"rocket",
    L"rubber", L"saddle", L"salmon", L"sapling", L"shovel", L"signal",
    L"silver", L"socket", L"spiral", L"sprout", L"stable", L"summit",
    L"switch", L"talon", L"teapot", L"temple", L"thistle", L"thunder",
    L"timber", L"tunnel", L"turbine", L"valley", L"velvet", L"walnut",
    L"willow", L"window", L"wombat", L"zebra"
};

static const int kCommonPasswordCount  = sizeof(kCommonPasswords)  / sizeof(kCommonPasswords[0]);
static const int kDictionaryWordCount  = sizeof(kDictionaryWords)  / sizeof(kDictionaryWords[0]);
static const int kKeyboardRunCount     = sizeof(kKeyboardRuns)     / sizeof(kKeyboardRuns[0]);
static const int kPassphraseWordCount  = sizeof(kPassphraseWords)  / sizeof(kPassphraseWords[0]);

// ---------------------------------------------------------------------------
// Small string helpers
// ---------------------------------------------------------------------------

static std::wstring ToLower(const std::wstring& text)
{
    std::wstring result = text;
    for (size_t i = 0; i < result.size(); ++i)
        result[i] = static_cast<wchar_t>(towlower(result[i]));
    return result;
}

// Turn leetspeak back into plain letters so "P@ssw0rd" is still spotted
// as the word "password".
static std::wstring Unleet(const std::wstring& text)
{
    std::wstring result;
    result.reserve(text.size());

    for (size_t i = 0; i < text.size(); ++i)
    {
        wchar_t c = static_cast<wchar_t>(towlower(text[i]));
        switch (c)
        {
            case L'4': case L'@': c = L'a'; break;
            case L'3': c = L'e'; break;
            case L'1': case L'!': case L'|': c = L'i'; break;
            case L'0': c = L'o'; break;
            case L'5': case L'$': c = L's'; break;
            case L'7': case L'+': c = L't'; break;
            case L'8': c = L'b'; break;
            case L'9': c = L'g'; break;
            default: break;
        }
        result += c;
    }
    return result;
}

static bool ContainsSubstring(const std::wstring& haystack, const std::wstring& needle)
{
    return haystack.find(needle) != std::wstring::npos;
}

static std::wstring FormatNumber(double value, int decimals)
{
    std::wostringstream stream;
    stream.setf(std::ios::fixed);
    stream.precision(decimals);
    stream << value;
    return stream.str();
}

// ---------------------------------------------------------------------------
// Crack-time estimate
//
// Worked in log10 space because a strong password produces a number far
// larger than a double can hold. Attack model: an offline attacker with
// consumer GPUs against a fast hash, 10 billion guesses per second.
// ---------------------------------------------------------------------------

static std::wstring FormatCrackTime(double entropyBits)
{
    const double guessesPerSecondLog10 = 10.0;   // 10,000,000,000 per second

    // Average case: half the keyspace, hence (bits - 1).
    double log10Seconds = (entropyBits - 1.0) * 0.30103 - guessesPerSecondLog10;

    if (log10Seconds < -1.0)  return L"instantly";
    if (log10Seconds <  0.0)  return L"less than a second";

    const double log10Minute = 1.77815;
    const double log10Hour   = 3.55630;
    const double log10Day    = 4.93651;
    const double log10Year   = 7.49901;

    if (log10Seconds < log10Minute)
        return FormatNumber(pow(10.0, log10Seconds), 0) + L" seconds";

    if (log10Seconds < log10Hour)
        return FormatNumber(pow(10.0, log10Seconds - log10Minute), 0) + L" minutes";

    if (log10Seconds < log10Day)
        return FormatNumber(pow(10.0, log10Seconds - log10Hour), 0) + L" hours";

    if (log10Seconds < log10Year)
        return FormatNumber(pow(10.0, log10Seconds - log10Day), 0) + L" days";

    double log10Years = log10Seconds - log10Year;

    if (log10Years < 3.0)
        return FormatNumber(pow(10.0, log10Years), 0) + L" years";
    if (log10Years < 6.0)
        return FormatNumber(pow(10.0, log10Years - 3.0), 1) + L" thousand years";
    if (log10Years < 9.0)
        return FormatNumber(pow(10.0, log10Years - 6.0), 1) + L" million years";
    if (log10Years < 12.0)
        return FormatNumber(pow(10.0, log10Years - 9.0), 1) + L" billion years";

    return L"longer than the age of the universe";
}

// ---------------------------------------------------------------------------
// Pattern detection helpers
// ---------------------------------------------------------------------------

// Three or more of the same character in a row: "aaa", "111"
static bool HasRepeatedRun(const std::wstring& text, std::wstring& found)
{
    int run = 1;
    for (size_t i = 1; i < text.size(); ++i)
    {
        if (towlower(text[i]) == towlower(text[i - 1]))
        {
            ++run;
            if (run >= 3)
            {
                found = text.substr(i - run + 1, run);
                return true;
            }
        }
        else
        {
            run = 1;
        }
    }
    return false;
}

// Four or more characters stepping up or down by one: "abcd", "4321"
static bool HasSequentialRun(const std::wstring& text, std::wstring& found)
{
    if (text.size() < 4) return false;

    for (size_t start = 0; start + 3 < text.size(); ++start)
    {
        int step = static_cast<int>(towlower(text[start + 1])) -
                   static_cast<int>(towlower(text[start]));
        if (step != 1 && step != -1) continue;

        size_t length = 2;
        while (start + length < text.size())
        {
            int nextStep = static_cast<int>(towlower(text[start + length])) -
                           static_cast<int>(towlower(text[start + length - 1]));
            if (nextStep != step) break;
            ++length;
        }

        if (length >= 4)
        {
            found = text.substr(start, length);
            return true;
        }
    }
    return false;
}

// A four-digit number that looks like a year: 1900 - 2099
static bool HasYearPattern(const std::wstring& text, std::wstring& found)
{
    for (size_t i = 0; i + 4 <= text.size(); ++i)
    {
        bool allDigits = true;
        for (size_t j = 0; j < 4; ++j)
        {
            if (!iswdigit(text[i + j])) { allDigits = false; break; }
        }
        if (!allDigits) continue;

        int year = _wtoi(text.substr(i, 4).c_str());
        if (year >= 1900 && year <= 2099)
        {
            found = text.substr(i, 4);
            return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// The audit itself
// ---------------------------------------------------------------------------

static AuditResult AuditPassword(const std::wstring& password)
{
    AuditResult result;
    result.length           = static_cast<int>(password.size());
    result.poolSize         = 0;
    result.rawEntropy       = 0.0;
    result.effectiveEntropy = 0.0;
    result.score            = 0;
    result.colour           = RGB(190, 40, 40);

    // --- Step 1: work out the character pool the attacker has to search ----
    bool hasLower = false, hasUpper = false, hasDigit = false, hasSymbol = false;

    for (size_t i = 0; i < password.size(); ++i)
    {
        wchar_t c = password[i];
        if (c >= L'a' && c <= L'z')      hasLower  = true;
        else if (c >= L'A' && c <= L'Z') hasUpper  = true;
        else if (c >= L'0' && c <= L'9') hasDigit  = true;
        else                             hasSymbol = true;
    }

    int pool = 0;
    if (hasLower)  pool += 26;
    if (hasUpper)  pool += 26;
    if (hasDigit)  pool += 10;
    if (hasSymbol) pool += 33;
    if (pool == 0) pool = 1;

    result.poolSize   = pool;
    result.rawEntropy = result.length * (log(static_cast<double>(pool)) / log(2.0));

    double penalty = 0.0;

    std::wstring lower  = ToLower(password);
    std::wstring plain  = Unleet(password);
    std::wstring found;

    // --- Step 2: record what the password is doing well -------------------
    int classCount = (hasLower ? 1 : 0) + (hasUpper ? 1 : 0) +
                     (hasDigit ? 1 : 0) + (hasSymbol ? 1 : 0);

    if (result.length >= 16)
        result.strengths.push_back(L"Excellent length (" + std::to_wstring(result.length) + L" characters).");
    else if (result.length >= 12)
        result.strengths.push_back(L"Good length (" + std::to_wstring(result.length) + L" characters).");

    if (classCount >= 4)
        result.strengths.push_back(L"Uses all four character types.");
    else if (classCount == 3)
        result.strengths.push_back(L"Uses three of the four character types.");

    if (hasSymbol)
        result.strengths.push_back(L"Includes symbols, which widens the search space.");

    // --- Step 3: hunt for predictable patterns ----------------------------
    bool isKnownPassword = false;

    for (int i = 0; i < kCommonPasswordCount; ++i)
    {
        std::wstring known = kCommonPasswords[i];
        if (lower == known || plain == known)
        {
            isKnownPassword = true;
            result.issues.push_back(L"CRITICAL: this is a known breached password. "
                                    L"It is tested in the first few seconds of any attack.");
            result.recommendations.push_back(
                L"Do not use this password anywhere. Replace it now, and change it on "
                L"every account where you have reused it.");
            break;
        }
    }

    std::wstring baseMatch;

    if (!isKnownPassword)
    {
        // Known password used as a base, e.g. "password123"
        for (int i = 0; i < kCommonPasswordCount; ++i)
        {
            std::wstring known = kCommonPasswords[i];
            if (known.size() >= 5 &&
                (ContainsSubstring(lower, known) || ContainsSubstring(plain, known)))
            {
                penalty += 14.0;
                baseMatch = known;
                result.issues.push_back(L"Built on the breached password \"" + known +
                                        L"\". Attackers try every common variation of these.");
                result.recommendations.push_back(
                    L"Start from something that is not on a leaked list. Adding numbers to "
                    L"the end of a known password adds almost no real protection.");
                break;
            }
        }

        // Dictionary words
        for (int i = 0; i < kDictionaryWordCount; ++i)
        {
            std::wstring word = kDictionaryWords[i];
            if (word.size() < 4) continue;
            if (word == baseMatch) continue;   // already reported above

            if (ContainsSubstring(lower, word) || ContainsSubstring(plain, word))
            {
                penalty += static_cast<double>(word.size()) * 1.8;

                if (ContainsSubstring(plain, word) && !ContainsSubstring(lower, word))
                {
                    result.issues.push_back(L"Contains the word \"" + word +
                                            L"\" hidden with character substitutions. "
                                            L"Cracking tools reverse these automatically.");
                    result.recommendations.push_back(
                        L"Swapping letters for lookalike symbols does not help. A tool tries "
                        L"\"a\" and \"@\" in the same pass.");
                }
                else
                {
                    result.issues.push_back(L"Contains the dictionary word \"" + word + L"\".");
                    result.recommendations.push_back(
                        L"Dictionary attacks search real words before random characters. "
                        L"Break the word up or use several unrelated words instead of one.");
                }
                break;
            }
        }

        // Keyboard runs
        for (int i = 0; i < kKeyboardRunCount; ++i)
        {
            std::wstring run = kKeyboardRuns[i];
            if (run.size() >= 4 && ContainsSubstring(lower, run))
            {
                penalty += 8.0;
                result.issues.push_back(L"Contains the keyboard pattern \"" + run +
                                        L"\". It looks random but follows the key layout.");
                result.recommendations.push_back(
                    L"Keyboard walks are in every cracking wordlist. Choose characters that "
                    L"are not neighbours on the keyboard.");
                break;
            }
        }

        // Sequences
        if (HasSequentialRun(password, found))
        {
            penalty += 7.0;
            result.issues.push_back(L"Contains the sequence \"" + found + L"\".");
            result.recommendations.push_back(
                L"Counting up or down is one of the first patterns a cracker tries.");
        }

        // Repeats
        if (HasRepeatedRun(password, found))
        {
            penalty += 5.0;
            result.issues.push_back(L"Repeats the same character: \"" + found + L"\".");
            result.recommendations.push_back(
                L"Repeated characters add length without adding real difficulty.");
        }

        // Years
        if (HasYearPattern(password, found))
        {
            penalty += 6.0;
            result.issues.push_back(L"Contains \"" + found +
                                    L"\", which looks like a year. There are only about 200 "
                                    L"plausible years to try.");
            result.recommendations.push_back(
                L"Birth years and graduation years are often guessable from social media.");
        }
    }
    else
    {
        // Known password: collapse the entropy entirely.
        penalty = result.rawEntropy - 4.0;
    }

    // --- Step 4: structural problems --------------------------------------
    if (result.length < 8)
    {
        penalty += 10.0;
        result.issues.push_back(L"Only " + std::to_wstring(result.length) +
                                L" characters. Anything under 8 falls to brute force quickly.");
        result.recommendations.push_back(
            L"Length is the single most effective change you can make. Every extra "
            L"character multiplies the work an attacker has to do.");
    }
    else if (result.length < 12)
    {
        penalty += 3.0;
        result.issues.push_back(L"At " + std::to_wstring(result.length) +
                                L" characters this is short by current standards.");
        result.recommendations.push_back(
            L"Aim for 14 characters or more. This is the cheapest improvement available.");
    }

    if (classCount == 1)
    {
        penalty += 7.0;
        if (hasDigit)
            result.issues.push_back(L"Digits only. The attacker searches a pool of just 10 characters.");
        else
            result.issues.push_back(L"One character type only, which keeps the search space small.");

        result.recommendations.push_back(
            L"Mix at least three of: lowercase, uppercase, digits and symbols.");
    }
    else if (classCount == 2)
    {
        penalty += 2.0;
        result.recommendations.push_back(
            L"Adding a third character type would widen the pool an attacker must search.");
    }

    // Predictable placement: capital at the front, digits at the back.
    if (result.length >= 4 && hasUpper && hasDigit)
    {
        bool capitalFirst  = (password[0] >= L'A' && password[0] <= L'Z');
        bool digitsAtEnd   = iswdigit(password[password.size() - 1]) != 0;
        bool upperOnlyOnce = true;
        for (size_t i = 1; i < password.size(); ++i)
        {
            if (password[i] >= L'A' && password[i] <= L'Z') { upperOnlyOnce = false; break; }
        }

        if (capitalFirst && digitsAtEnd && upperOnlyOnce)
        {
            penalty += 4.0;
            result.issues.push_back(L"Follows the predictable shape: capital first, digits last. "
                                    L"Most human passwords do this.");
            result.recommendations.push_back(
                L"Put uppercase letters and digits in unexpected positions instead of the "
                L"start and the end.");
        }
    }

    // --- Step 5: final numbers --------------------------------------------
    result.effectiveEntropy = result.rawEntropy - penalty;
    if (result.effectiveEntropy < 0.0) result.effectiveEntropy = 0.0;

    if (result.length == 0)
    {
        result.effectiveEntropy = 0.0;
        result.rawEntropy       = 0.0;
    }

    result.score = static_cast<int>(result.effectiveEntropy * 1.05);
    if (result.score > 100) result.score = 100;
    if (result.score < 0)   result.score = 0;

    result.crackTime = FormatCrackTime(result.effectiveEntropy);

    if      (result.score >= 80) { result.rating = L"EXCELLENT"; result.colour = RGB(20, 130, 60);  }
    else if (result.score >= 60) { result.rating = L"STRONG";    result.colour = RGB(60, 140, 70);  }
    else if (result.score >= 40) { result.rating = L"FAIR";      result.colour = RGB(200, 140, 20); }
    else if (result.score >= 20) { result.rating = L"WEAK";      result.colour = RGB(210, 100, 20); }
    else                         { result.rating = L"CRITICAL";  result.colour = RGB(190, 40, 40);  }

    // --- Step 6: show the payoff of the top recommendation ----------------
    if (result.score < 80)
    {
        double improved = result.effectiveEntropy +
                          4.0 * (log(static_cast<double>(pool > 26 ? pool : 62)) / log(2.0));
        result.improvementNote =
            L"Adding four more unpredictable characters would move the estimate from " +
            result.crackTime + L" to " + FormatCrackTime(improved) + L".";
    }
    else
    {
        result.improvementNote =
            L"This password is already past the point where brute force is realistic. "
            L"The remaining risk is reuse - never use it on more than one account.";
    }

    if (result.recommendations.empty())
    {
        result.recommendations.push_back(
            L"No predictable patterns detected. Store this in a password manager rather "
            L"than trying to memorise it.");
    }

    return result;
}

// ---------------------------------------------------------------------------
// Passphrase generator
// ---------------------------------------------------------------------------

static std::wstring GeneratePassphrase()
{
    static std::mt19937 generator(static_cast<unsigned int>(GetTickCount64()));

    std::uniform_int_distribution<int> wordPick(0, kPassphraseWordCount - 1);
    std::uniform_int_distribution<int> digitPick(10, 99);
    std::uniform_int_distribution<int> sepPick(0, 5);
    std::uniform_int_distribution<int> casePick(0, 1);

    const wchar_t separators[] = { L'-', L'.', L'_', L'!', L'#', L'&' };
    wchar_t separator = separators[sepPick(generator)];

    std::wstring phrase;
    for (int i = 0; i < 4; ++i)
    {
        std::wstring word = kPassphraseWords[wordPick(generator)];
        if (casePick(generator) == 1)
            word[0] = static_cast<wchar_t>(towupper(word[0]));

        if (i > 0) phrase += separator;
        phrase += word;
    }

    phrase += separator;
    phrase += std::to_wstring(digitPick(generator));

    return phrase;
}

// ---------------------------------------------------------------------------
// Build the report text shown in the output box
// ---------------------------------------------------------------------------

static std::wstring BuildReport(const std::wstring& password, const AuditResult& result)
{
    UNREFERENCED_PARAMETER(password);

    std::wostringstream report;
    const std::wstring line = L"------------------------------------------------------------\r\n";

    report << L"AUDIT SUMMARY\r\n" << line;
    report << L"  Length            : " << result.length << L" characters\r\n";
    report << L"  Character pool    : " << result.poolSize << L" possible characters\r\n";
    report << L"  Raw entropy       : " << FormatNumber(result.rawEntropy, 1) << L" bits\r\n";
    report << L"  Effective entropy : " << FormatNumber(result.effectiveEntropy, 1)
           << L" bits (after pattern penalties)\r\n";
    report << L"  Estimated crack   : " << result.crackTime << L"\r\n";
    report << L"\r\n  Attack model: offline attacker, 10 billion guesses per second.\r\n\r\n";

    if (!result.strengths.empty())
    {
        report << L"WHAT THIS PASSWORD DOES WELL\r\n" << line;
        for (size_t i = 0; i < result.strengths.size(); ++i)
            report << L"  + " << result.strengths[i] << L"\r\n";
        report << L"\r\n";
    }

    report << L"WEAKNESSES DETECTED\r\n" << line;
    if (result.issues.empty())
    {
        report << L"  None. No dictionary words, keyboard patterns, sequences,\r\n"
               << L"  repeats or year patterns were found.\r\n\r\n";
    }
    else
    {
        for (size_t i = 0; i < result.issues.size(); ++i)
            report << L"  " << (i + 1) << L". " << result.issues[i] << L"\r\n";
        report << L"\r\n";
    }

    report << L"RECOMMENDATIONS\r\n" << line;
    for (size_t i = 0; i < result.recommendations.size(); ++i)
        report << L"  -> " << result.recommendations[i] << L"\r\n";

    report << L"\r\nIMPACT OF IMPROVING\r\n" << line;
    report << L"  " << result.improvementNote << L"\r\n";

    report << L"\r\n" << line;
    report << L"  Nothing you type is saved, logged or sent anywhere.\r\n";
    report << L"  All analysis happens on this computer.\r\n";

    return report.str();
}

// ---------------------------------------------------------------------------
// Run an audit against whatever is in the password box
// ---------------------------------------------------------------------------

static void RunAudit()
{
    int length = GetWindowTextLengthW(gPasswordEdit);

    if (length <= 0)
    {
        MessageBoxW(gMainWnd,
                    L"Please enter a password to audit.",
                    L"No Input",
                    MB_OK | MB_ICONINFORMATION);
        return;
    }

    if (length > 128)
    {
        MessageBoxW(gMainWnd,
                    L"Please enter a password of 128 characters or fewer.",
                    L"Input Too Long",
                    MB_OK | MB_ICONWARNING);
        return;
    }

    std::vector<wchar_t> buffer(static_cast<size_t>(length) + 1, L'\0');
    GetWindowTextW(gPasswordEdit, &buffer[0], length + 1);
    std::wstring password(&buffer[0]);

    // Clear the buffer so the raw password does not linger in memory.
    for (size_t i = 0; i < buffer.size(); ++i) buffer[i] = L'\0';

    if (password.empty())
    {
        MessageBoxW(gMainWnd,
                    L"Please enter a password to audit.",
                    L"No Input",
                    MB_OK | MB_ICONINFORMATION);
        return;
    }

    AuditResult result = AuditPassword(password);

    std::wostringstream scoreText;
    scoreText << L"Score: " << result.score << L" / 100      "
              << result.rating << L"      Crack time: " << result.crackTime;

    gScoreColour = result.colour;
    SetWindowTextW(gScoreLabel, scoreText.str().c_str());
    InvalidateRect(gScoreLabel, NULL, TRUE);

    SetWindowTextW(gOutputEdit, BuildReport(password, result).c_str());
}

// ---------------------------------------------------------------------------
// Window procedure
// ---------------------------------------------------------------------------

static LRESULT CALLBACK WindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_CREATE:
    {
        gUiFont = CreateFontW(-15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                              DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                              CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

        gTitleFont = CreateFontW(-26, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                                 DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                 CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

        gScoreFont = CreateFontW(-19, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                                 DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                 CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

        gMonoFont = CreateFontW(-13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");

        HWND title = CreateWindowExW(
            0, L"STATIC", L"Password Strength Auditor",
            WS_CHILD | WS_VISIBLE | SS_CENTER,
            20, 16, 680, 34,
            hwnd, NULL, NULL, NULL);
        SendMessageW(title, WM_SETFONT, (WPARAM)gTitleFont, TRUE);

        HWND subtitle = CreateWindowExW(
            0, L"STATIC",
            L"Checks a password against real attack techniques and explains how to fix it.",
            WS_CHILD | WS_VISIBLE | SS_CENTER,
            20, 52, 680, 20,
            hwnd, NULL, NULL, NULL);
        SendMessageW(subtitle, WM_SETFONT, (WPARAM)gUiFont, TRUE);

        HWND promptLabel = CreateWindowExW(
            0, L"STATIC", L"Password to audit:",
            WS_CHILD | WS_VISIBLE,
            20, 90, 200, 20,
            hwnd, NULL, NULL, NULL);
        SendMessageW(promptLabel, WM_SETFONT, (WPARAM)gUiFont, TRUE);

        gPasswordEdit = CreateWindowExW(
            WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL | ES_PASSWORD,
            20, 112, 560, 28,
            hwnd, (HMENU)IDC_PASSWORD_EDIT, NULL, NULL);
        SendMessageW(gPasswordEdit, WM_SETFONT, (WPARAM)gUiFont, TRUE);
        SendMessageW(gPasswordEdit, EM_SETLIMITTEXT, (WPARAM)128, 0);

        gShowCheck = CreateWindowExW(
            0, L"BUTTON", L"Show",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
            594, 117, 100, 20,
            hwnd, (HMENU)IDC_SHOW_CHECK, NULL, NULL);
        SendMessageW(gShowCheck, WM_SETFONT, (WPARAM)gUiFont, TRUE);

        HWND analyseButton = CreateWindowExW(
            0, L"BUTTON", L"Audit Password",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
            20, 152, 170, 34,
            hwnd, (HMENU)IDC_ANALYSE_BTN, NULL, NULL);
        SendMessageW(analyseButton, WM_SETFONT, (WPARAM)gUiFont, TRUE);

        HWND generateButton = CreateWindowExW(
            0, L"BUTTON", L"Suggest a Strong Passphrase",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            200, 152, 250, 34,
            hwnd, (HMENU)IDC_GENERATE_BTN, NULL, NULL);
        SendMessageW(generateButton, WM_SETFONT, (WPARAM)gUiFont, TRUE);

        HWND clearButton = CreateWindowExW(
            0, L"BUTTON", L"Clear",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            460, 152, 120, 34,
            hwnd, (HMENU)IDC_CLEAR_BTN, NULL, NULL);
        SendMessageW(clearButton, WM_SETFONT, (WPARAM)gUiFont, TRUE);

        gScoreLabel = CreateWindowExW(
            0, L"STATIC", L"Score: -- / 100",
            WS_CHILD | WS_VISIBLE,
            20, 200, 680, 28,
            hwnd, (HMENU)IDC_SCORE_LABEL, NULL, NULL);
        SendMessageW(gScoreLabel, WM_SETFONT, (WPARAM)gScoreFont, TRUE);

        gOutputEdit = CreateWindowExW(
            WS_EX_CLIENTEDGE, L"EDIT",
            L"Enter a password above and press Audit Password.\r\n\r\n"
            L"Nothing you type is saved, logged or sent anywhere. All analysis\r\n"
            L"happens on this computer.",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_TABSTOP |
            ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
            20, 236, 680, 392,
            hwnd, (HMENU)IDC_OUTPUT_EDIT, NULL, NULL);
        SendMessageW(gOutputEdit, WM_SETFONT, (WPARAM)gMonoFont, TRUE);

        return 0;
    }

    case WM_CTLCOLORSTATIC:
    {
        HDC  dc      = (HDC)wParam;
        HWND control = (HWND)lParam;

        SetBkMode(dc, TRANSPARENT);

        if (control == gScoreLabel)
            SetTextColor(dc, gScoreColour);
        else
            SetTextColor(dc, RGB(40, 40, 40));

        return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);
    }

    case WM_COMMAND:
    {
        switch (LOWORD(wParam))
        {
        case IDC_ANALYSE_BTN:
            RunAudit();
            return 0;

        case IDC_GENERATE_BTN:
        {
            std::wstring phrase = GeneratePassphrase();
            SendMessageW(gShowCheck, BM_SETCHECK, (WPARAM)BST_CHECKED, 0);
            SendMessageW(gPasswordEdit, EM_SETPASSWORDCHAR, 0, 0);
            InvalidateRect(gPasswordEdit, NULL, TRUE);
            SetWindowTextW(gPasswordEdit, phrase.c_str());
            RunAudit();
            return 0;
        }

        case IDC_CLEAR_BTN:
            SetWindowTextW(gPasswordEdit, L"");
            SetWindowTextW(gScoreLabel, L"Score: -- / 100");
            gScoreColour = RGB(70, 70, 70);
            InvalidateRect(gScoreLabel, NULL, TRUE);
            SetWindowTextW(gOutputEdit,
                L"Enter a password above and press Audit Password.\r\n\r\n"
                L"Nothing you type is saved, logged or sent anywhere. All analysis\r\n"
                L"happens on this computer.");
            SetFocus(gPasswordEdit);
            return 0;

        case IDC_SHOW_CHECK:
        {
            LRESULT checked = SendMessageW(gShowCheck, BM_GETCHECK, 0, 0);
            if (checked == BST_CHECKED)
                SendMessageW(gPasswordEdit, EM_SETPASSWORDCHAR, 0, 0);
            else
                SendMessageW(gPasswordEdit, EM_SETPASSWORDCHAR, (WPARAM)L'\x25CF', 0);

            InvalidateRect(gPasswordEdit, NULL, TRUE);
            return 0;
        }

        default:
            break;
        }
        break;
    }

    case WM_DESTROY:
        if (gUiFont)    DeleteObject(gUiFont);
        if (gTitleFont) DeleteObject(gTitleFont);
        if (gScoreFont) DeleteObject(gScoreFont);
        if (gMonoFont)  DeleteObject(gMonoFont);
        PostQuitMessage(0);
        return 0;

    default:
        break;
    }

    return DefWindowProcW(hwnd, message, wParam, lParam);
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                      _In_opt_ HINSTANCE hPrevInstance,
                      _In_ LPWSTR lpCmdLine,
                      _In_ int nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    const wchar_t CLASS_NAME[] = L"PasswordAuditorWindowClass";

    WNDCLASSEXW windowClass = { 0 };
    windowClass.cbSize        = sizeof(WNDCLASSEXW);
    windowClass.style         = CS_HREDRAW | CS_VREDRAW;
    windowClass.lpfnWndProc   = WindowProc;
    windowClass.hInstance     = hInstance;
    windowClass.hCursor       = LoadCursorW(NULL, IDC_ARROW);
    windowClass.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    windowClass.lpszClassName = CLASS_NAME;
    windowClass.hIcon         = LoadIconW(hInstance, MAKEINTRESOURCEW(101));
    windowClass.hIconSm       = LoadIconW(hInstance, MAKEINTRESOURCEW(101));

    if (!RegisterClassExW(&windowClass))
    {
        MessageBoxW(NULL, L"Failed to register the window class.",
                    L"Startup Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    RECT desired = { 0, 0, 720, 648 };
    AdjustWindowRect(&desired, WS_OVERLAPPEDWINDOW, FALSE);

    gMainWnd = CreateWindowExW(
        0,
        CLASS_NAME,
        L"Password Strength Auditor",
        WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_THICKFRAME,
        CW_USEDEFAULT, CW_USEDEFAULT,
        desired.right - desired.left,
        desired.bottom - desired.top,
        NULL, NULL, hInstance, NULL);

    if (gMainWnd == NULL)
    {
        MessageBoxW(NULL, L"Failed to create the application window.",
                    L"Startup Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    // Mask the password field by default.
    SendMessageW(gPasswordEdit, EM_SETPASSWORDCHAR, (WPARAM)L'\x25CF', 0);

    ShowWindow(gMainWnd, nCmdShow);
    UpdateWindow(gMainWnd);
    SetFocus(gPasswordEdit);

    MSG message;
    while (GetMessageW(&message, NULL, 0, 0) > 0)
    {
        if (!IsDialogMessageW(gMainWnd, &message))
        {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }

    return (int)message.wParam;
}
