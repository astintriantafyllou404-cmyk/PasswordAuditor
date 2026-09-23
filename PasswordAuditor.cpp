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
#include <commdlg.h>
#include <wincrypt.h>
#include <winhttp.h>
#include <string>
#include <vector>
#include <sstream>
#include <cmath>
#include <cwctype>
#include <cstdlib>
#include <random>
#include <algorithm>
#include <iterator>

#if defined(_MSC_VER)
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "winhttp.lib")
#endif

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
#define IDC_METER           108
#define IDC_SAVE_BTN        109
#define IDC_BREACH_BTN      110
#define IDM_THEME_DEFAULT   201
#define IDM_THEME_WARM      202
#define IDM_THEME_DARK      203
#define IDM_THEME_CALLME    204
#define IDM_SHOW_DAD        210
#define IDB_DAD_PHOTO       301
#define IDM_SHOW_COMPARE    211
#define IDM_SHOW_REUSE      212

#define IDC_CMP_EDIT_A          401
#define IDC_CMP_EDIT_B          402
#define IDC_CMP_BUTTON          403
#define IDC_CMP_OUTPUT          404

#define IDC_REUSE_CHECK_GMAIL   421
#define IDC_REUSE_CHECK_STEAM   422
#define IDC_REUSE_CHECK_DISCORD 423
#define IDC_REUSE_CHECK_SCHOOL  424
#define IDC_REUSE_CHECK_BANKING 425
#define IDC_REUSE_CHECK_SOCIAL  426
#define IDC_REUSE_BUTTON        427
#define IDC_REUSE_OUTPUT        428

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------
static HWND     gMainWnd        = NULL;
static HWND     gPasswordEdit   = NULL;
static HWND     gShowCheck      = NULL;
static HWND     gOutputEdit     = NULL;
static HWND     gScoreLabel     = NULL;
static HWND     gMeterCtl       = NULL;
static HFONT    gUiFont         = NULL;
static HFONT    gTitleFont      = NULL;
static HFONT    gScoreFont      = NULL;
static HFONT    gMonoFont       = NULL;
static COLORREF gScoreColour    = RGB(70, 70, 70);
static int      gMeterScore     = 0;      // 0-100, drives the strength meter fill
static std::wstring gLastReportText;      // last audit report, for Save Report
static bool     gHasResult      = false;  // has an audit been run yet?

// ---------------------------------------------------------------------------
// Themes
// ---------------------------------------------------------------------------
struct ThemeColours
{
    COLORREF windowBg;
    COLORREF textColour;
    COLORREF editBg;
    COLORREF editText;
    COLORREF meterEmptyBg;
    COLORREF meterBorder;
};

static const ThemeColours kThemeDefault = {
    RGB(240, 240, 240), // window background
    RGB(30,  30,  30),  // text
    RGB(255, 255, 255), // edit box background
    RGB(20,  20,  20),  // edit box text
    RGB(228, 228, 228), // meter empty track
    RGB(160, 160, 160)  // meter border
};

static const ThemeColours kThemeWarm = {
    RGB(245, 235, 219), // beige window background
    RGB(92,  60,  42),  // light-brown text
    RGB(255, 250, 240), // warm cream edit background
    RGB(74,  48,  34),  // brown edit text
    RGB(210, 227, 238), // baby blue meter track
    RGB(184, 138, 94)   // light-brown meter border
};

static const ThemeColours kThemeDark = {
    RGB(32,  34,  38),
    RGB(228, 230, 235),
    RGB(24,  26,  30),
    RGB(218, 220, 226),
    RGB(50,  53,  60),
    RGB(95,  100, 112)
};

// Warm cream background with pink/teal/mint/mustard accents - an original
// palette inspired by a retro pastel aesthetic, not any copyrighted artwork.
static const ThemeColours kThemeCallMe = {
    RGB(247, 236, 208), // cream window background
    RGB(74,  52,  38),  // dark brown text
    RGB(255, 250, 235), // warm off-white edit background
    RGB(60,  42,  30),  // dark brown edit text
    RGB(178, 224, 214), // mint-teal meter track
    RGB(212, 163, 55)   // mustard meter border
};

static ThemeColours gTheme          = kThemeDefault;
static HBRUSH       gWindowBgBrush  = NULL;
static HBRUSH       gEditBgBrush    = NULL;
static int          gActiveThemeId  = 0; // 0 = Default, 1 = Warm, 2 = Dark

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

// entropyBits: effective entropy of the password.
// guessesPerSecondLog10: log10 of the attacker's guess rate. Different attack
// scenarios have wildly different rates, which is why the same password can
// be "instant" for one attacker and "centuries" for another.
static std::wstring FormatCrackTimeAtRate(double entropyBits, double guessesPerSecondLog10)
{
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

// Named attack scenarios, as log10(guesses per second). Real crackers do not
// all move at the same speed - showing a range is more honest than one number.
static const double kRateOnlineThrottled = 1.0;   // ~10/sec, a login form with rate limiting
static const double kRateOfflineSlowHash = 4.0;   // ~10,000/sec, a slow salted hash (bcrypt/Argon2)
static const double kRateOfflineFastHash = 10.0;  // ~10 billion/sec, a fast unsalted hash on GPUs

// Default: assumes the worst realistic case (fast offline hash), matching
// the original single-scenario behaviour used elsewhere in this file.
static std::wstring FormatCrackTime(double entropyBits)
{
    return FormatCrackTimeAtRate(entropyBits, kRateOfflineFastHash);
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
           << L" bits (after pattern penalties)\r\n\r\n";

    report << L"CRACK TIME BY ATTACK SCENARIO\r\n" << line;
    report << L"  Online, rate-limited login   (~10 guesses/sec)       : "
           << FormatCrackTimeAtRate(result.effectiveEntropy, kRateOnlineThrottled) << L"\r\n";
    report << L"  Offline, slow salted hash    (~10 thousand/sec)      : "
           << FormatCrackTimeAtRate(result.effectiveEntropy, kRateOfflineSlowHash) << L"\r\n";
    report << L"  Offline, fast hash on GPU    (~10 billion/sec)       : "
           << FormatCrackTimeAtRate(result.effectiveEntropy, kRateOfflineFastHash) << L"\r\n";
    report << L"\r\n  The same password can be effectively uncrackable on one system and\r\n"
           << L"  trivial on another - it depends entirely on how the target stores it.\r\n\r\n";

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
// A small, separate popup window that shows an embedded photo. Deliberately
// kept isolated from the main window (its own class, its own WndProc) so it
// can't interact with or affect the carefully-tuned main layout at all.
// ---------------------------------------------------------------------------

static LRESULT CALLBACK DadPopupProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    static HBITMAP dadBitmap = NULL;

    switch (msg)
    {
    case WM_CREATE:
        dadBitmap = LoadBitmapW(GetModuleHandleW(NULL), MAKEINTRESOURCEW(IDB_DAD_PHOTO));
        return 0;

    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(hwnd, &ps);

        RECT rc;
        GetClientRect(hwnd, &rc);
        HBRUSH bg = CreateSolidBrush(RGB(247, 236, 208));
        FillRect(dc, &rc, bg);
        DeleteObject(bg);

        if (dadBitmap)
        {
            BITMAP bm;
            GetObject(dadBitmap, sizeof(bm), &bm);

            HDC memDC = CreateCompatibleDC(dc);
            HGDIOBJ oldBmp = SelectObject(memDC, dadBitmap);
            int x = (rc.right - bm.bmWidth) / 2;
            BitBlt(dc, x, 14, bm.bmWidth, bm.bmHeight, memDC, 0, 0, SRCCOPY);
            SelectObject(memDC, oldBmp);
            DeleteDC(memDC);

            RECT captionRc = { 10, 14 + bm.bmHeight + 12, rc.right - 10, rc.bottom - 10 };
            SetBkMode(dc, TRANSPARENT);
            SetTextColor(dc, RGB(74, 52, 38));
            HFONT font = CreateFontW(20, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
            HGDIOBJ oldFont = SelectObject(dc, font);
            DrawTextW(dc, L"Dad Mode: Activated", -1, &captionRc, DT_CENTER | DT_WORDBREAK);
            SelectObject(dc, oldFont);
            DeleteObject(font);
        }

        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_DESTROY:
        if (dadBitmap) { DeleteObject(dadBitmap); dadBitmap = NULL; }
        return 0;

    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static void ShowDadPopup()
{
    static bool classRegistered = false;
    const wchar_t CLASS_NAME[] = L"DadPopupWindowClass";

    if (!classRegistered)
    {
        WNDCLASSEXW wc = {};
        wc.cbSize        = sizeof(wc);
        wc.lpfnWndProc   = DadPopupProc;
        wc.hInstance     = GetModuleHandleW(NULL);
        wc.lpszClassName = CLASS_NAME;
        wc.hCursor       = LoadCursorW(NULL, IDC_ARROW);
        wc.hbrBackground = NULL; // painted manually in WM_PAINT
        RegisterClassExW(&wc);
        classRegistered = true;
    }

    RECT desired = { 0, 0, 280, 330 };
    AdjustWindowRect(&desired, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, FALSE);

    HWND popup = CreateWindowExW(
        WS_EX_DLGMODALFRAME,
        CLASS_NAME,
        L"A Small Surprise",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT,
        desired.right - desired.left,
        desired.bottom - desired.top,
        gMainWnd, NULL, GetModuleHandleW(NULL), NULL);

    if (popup)
    {
        ShowWindow(popup, SW_SHOW);
        UpdateWindow(popup);
    }
}

// ---------------------------------------------------------------------------
// Password Comparison Mode - reuses AuditPassword, the same scoring engine
// behind Audit Password, so both tools always agree with each other.
// ---------------------------------------------------------------------------

static HWND gCmpEditA  = NULL;
static HWND gCmpEditB  = NULL;
static HWND gCmpOutput = NULL;

static void RunComparison(HWND popupHwnd)
{
    wchar_t bufA[129] = L"";
    wchar_t bufB[129] = L"";
    GetWindowTextW(gCmpEditA, bufA, 129);
    GetWindowTextW(gCmpEditB, bufB, 129);
    std::wstring pwA(bufA), pwB(bufB);

    if (pwA.empty() || pwB.empty())
    {
        MessageBoxW(popupHwnd, L"Enter both passwords to compare.",
                    L"Nothing to Compare", MB_OK | MB_ICONINFORMATION);
        return;
    }

    AuditResult resultA = AuditPassword(pwA);
    AuditResult resultB = AuditPassword(pwB);

    std::wstring winner;
    if      (resultA.score > resultB.score) winner = L"Password A";
    else if (resultB.score > resultA.score) winner = L"Password B";
    else                                     winner = L"Tie";

    std::wstringstream out;
    out << L"Winner: " << winner << L"\r\n";
    out << L"--------------------------------------------\r\n\r\n";
    out << L"Password A\r\n";
    out << L"  Score: " << resultA.score << L"/100 (" << resultA.rating << L")\r\n";
    out << L"  Crack Time: " << resultA.crackTime << L"\r\n\r\n";
    out << L"Password B\r\n";
    out << L"  Score: " << resultB.score << L"/100 (" << resultB.rating << L")\r\n";
    out << L"  Crack Time: " << resultB.crackTime << L"\r\n";

    SetWindowTextW(gCmpOutput, out.str().c_str());
}

static LRESULT CALLBACK ComparePopupProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_CREATE:
    {
        HFONT font = CreateFontW(-15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
        HFONT boldFont = CreateFontW(-15, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
        HFONT monoFont = CreateFontW(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");

        HWND note = CreateWindowExW(0, L"STATIC",
            L"Neither password is saved, logged or sent anywhere.",
            WS_CHILD | WS_VISIBLE, 16, 12, 420, 18, hwnd, NULL, NULL, NULL);
        SendMessageW(note, WM_SETFONT, (WPARAM)font, TRUE);

        HWND labelA = CreateWindowExW(0, L"STATIC", L"Password A:",
            WS_CHILD | WS_VISIBLE, 16, 40, 200, 18, hwnd, NULL, NULL, NULL);
        SendMessageW(labelA, WM_SETFONT, (WPARAM)font, TRUE);

        gCmpEditA = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            16, 60, 420, 26, hwnd, (HMENU)IDC_CMP_EDIT_A, NULL, NULL);
        SendMessageW(gCmpEditA, WM_SETFONT, (WPARAM)font, TRUE);

        HWND labelB = CreateWindowExW(0, L"STATIC", L"Password B:",
            WS_CHILD | WS_VISIBLE, 16, 98, 200, 18, hwnd, NULL, NULL, NULL);
        SendMessageW(labelB, WM_SETFONT, (WPARAM)font, TRUE);

        gCmpEditB = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            16, 118, 420, 26, hwnd, (HMENU)IDC_CMP_EDIT_B, NULL, NULL);
        SendMessageW(gCmpEditB, WM_SETFONT, (WPARAM)font, TRUE);

        HWND button = CreateWindowExW(0, L"BUTTON", L"Compare Passwords",
            WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
            16, 156, 200, 32, hwnd, (HMENU)IDC_CMP_BUTTON, NULL, NULL);
        SendMessageW(button, WM_SETFONT, (WPARAM)boldFont, TRUE);

        gCmpOutput = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT",
            L"Enter two passwords above and press Compare Passwords.",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
            16, 198, 420, 170, hwnd, (HMENU)IDC_CMP_OUTPUT, NULL, NULL);
        SendMessageW(gCmpOutput, WM_SETFONT, (WPARAM)monoFont, TRUE);

        return 0;
    }

    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_CMP_BUTTON)
        {
            RunComparison(hwnd);
            return 0;
        }
        break;

    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static void ShowComparePopup()
{
    static bool classRegistered = false;
    const wchar_t CLASS_NAME[] = L"ComparePopupWindowClass";

    if (!classRegistered)
    {
        WNDCLASSEXW wc = {};
        wc.cbSize        = sizeof(wc);
        wc.lpfnWndProc   = ComparePopupProc;
        wc.hInstance     = GetModuleHandleW(NULL);
        wc.lpszClassName = CLASS_NAME;
        wc.hCursor       = LoadCursorW(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        RegisterClassExW(&wc);
        classRegistered = true;
    }

    RECT desired = { 0, 0, 460, 410 };
    AdjustWindowRect(&desired, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, FALSE);

    HWND popup = CreateWindowExW(
        WS_EX_DLGMODALFRAME,
        CLASS_NAME,
        L"Compare Passwords",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT,
        desired.right - desired.left,
        desired.bottom - desired.top,
        gMainWnd, NULL, GetModuleHandleW(NULL), NULL);

    if (popup)
    {
        ShowWindow(popup, SW_SHOW);
        UpdateWindow(popup);
    }
}

// ---------------------------------------------------------------------------
// Password Reuse Risk Calculator
// ---------------------------------------------------------------------------

struct ReuseServiceCheckbox { int id; const wchar_t* label; };

static const ReuseServiceCheckbox kReuseServices[] = {
    { IDC_REUSE_CHECK_GMAIL,   L"Gmail / Email"           },
    { IDC_REUSE_CHECK_STEAM,   L"Steam / Gaming"          },
    { IDC_REUSE_CHECK_DISCORD, L"Discord"                 },
    { IDC_REUSE_CHECK_SCHOOL,  L"School / Student Portal" },
    { IDC_REUSE_CHECK_BANKING, L"Banking"                 },
    { IDC_REUSE_CHECK_SOCIAL,  L"Social Media"             },
};
static const int kReuseServiceCount = sizeof(kReuseServices) / sizeof(kReuseServices[0]);

static HWND gReuseOutput = NULL;

static void RunReuseCalculation(HWND popupHwnd)
{
    std::vector<std::wstring> checked;
    for (int i = 0; i < kReuseServiceCount; ++i)
    {
        HWND box = GetDlgItem(popupHwnd, kReuseServices[i].id);
        if (box && SendMessageW(box, BM_GETCHECK, 0, 0) == BST_CHECKED)
            checked.push_back(kReuseServices[i].label);
    }

    if (checked.empty())
    {
        MessageBoxW(popupHwnd, L"Tick at least one service this password is used on.",
                    L"Nothing Selected", MB_OK | MB_ICONINFORMATION);
        return;
    }

    int count = static_cast<int>(checked.size());
    std::wstring risk;
    if      (count <= 1) risk = L"LOW";
    else if (count <= 3) risk = L"MEDIUM";
    else if (count <= 5) risk = L"HIGH";
    else                  risk = L"CRITICAL";

    std::wstringstream out;
    out << L"Risk Level: " << risk << L"\r\n";
    out << L"--------------------------------------------\r\n\r\n";
    out << L"A breach of just one of these services could expose " << count
        << (count == 1 ? L" account" : L" separate accounts")
        << L", since the same password would let an attacker straight into "
           L"the others too.\r\n\r\nServices this password is reused on:\r\n";
    for (const auto& s : checked)
        out << L"  - " << s << L"\r\n";
    out << L"\r\nUse a different password for each service, or a password "
           L"manager, so one leak stays contained to a single account.";

    SetWindowTextW(gReuseOutput, out.str().c_str());
}

static LRESULT CALLBACK ReusePopupProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_CREATE:
    {
        HFONT font = CreateFontW(-15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
        HFONT boldFont = CreateFontW(-15, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
        HFONT monoFont = CreateFontW(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");

        HWND note = CreateWindowExW(0, L"STATIC",
            L"Tick every place you use this exact password:",
            WS_CHILD | WS_VISIBLE, 16, 12, 320, 18, hwnd, NULL, NULL, NULL);
        SendMessageW(note, WM_SETFONT, (WPARAM)font, TRUE);

        int y = 38;
        for (int i = 0; i < kReuseServiceCount; ++i)
        {
            HWND box = CreateWindowExW(0, L"BUTTON", kReuseServices[i].label,
                WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                16, y, 300, 22, hwnd, (HMENU)kReuseServices[i].id, NULL, NULL);
            SendMessageW(box, WM_SETFONT, (WPARAM)font, TRUE);
            y += 26;
        }

        HWND button = CreateWindowExW(0, L"BUTTON", L"Calculate Risk",
            WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
            16, y + 8, 180, 32, hwnd, (HMENU)IDC_REUSE_BUTTON, NULL, NULL);
        SendMessageW(button, WM_SETFONT, (WPARAM)boldFont, TRUE);

        gReuseOutput = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT",
            L"Tick the services above and press Calculate Risk.",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
            16, y + 48, 320, 160, hwnd, (HMENU)IDC_REUSE_OUTPUT, NULL, NULL);
        SendMessageW(gReuseOutput, WM_SETFONT, (WPARAM)monoFont, TRUE);

        return 0;
    }

    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_REUSE_BUTTON)
        {
            RunReuseCalculation(hwnd);
            return 0;
        }
        break;

    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static void ShowReusePopup()
{
    static bool classRegistered = false;
    const wchar_t CLASS_NAME[] = L"ReusePopupWindowClass";

    if (!classRegistered)
    {
        WNDCLASSEXW wc = {};
        wc.cbSize        = sizeof(wc);
        wc.lpfnWndProc   = ReusePopupProc;
        wc.hInstance     = GetModuleHandleW(NULL);
        wc.lpszClassName = CLASS_NAME;
        wc.hCursor       = LoadCursorW(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        RegisterClassExW(&wc);
        classRegistered = true;
    }

    int contentBottom = 38 + kReuseServiceCount * 26 + 48 + 160 + 20;
    RECT desired = { 0, 0, 360, contentBottom };
    AdjustWindowRect(&desired, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, FALSE);

    HWND popup = CreateWindowExW(
        WS_EX_DLGMODALFRAME,
        CLASS_NAME,
        L"Password Reuse Risk",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT,
        desired.right - desired.left,
        desired.bottom - desired.top,
        gMainWnd, NULL, GetModuleHandleW(NULL), NULL);

    if (popup)
    {
        ShowWindow(popup, SW_SHOW);
        UpdateWindow(popup);
    }
}

// ---------------------------------------------------------------------------
// Blend a colour toward a background colour, for a soft "washed out" look
// without needing real alpha-blending (which isn't reliable in plain GDI
// on every display).
// ---------------------------------------------------------------------------

static COLORREF BlendColour(COLORREF foreground, COLORREF background, double alpha)
{
    int r = static_cast<int>(GetRValue(foreground) * alpha + GetRValue(background) * (1.0 - alpha));
    int g = static_cast<int>(GetGValue(foreground) * alpha + GetGValue(background) * (1.0 - alpha));
    int b = static_cast<int>(GetBValue(foreground) * alpha + GetBValue(background) * (1.0 - alpha));
    return RGB(r, g, b);
}

struct FlowerSpec
{
    bool     leftSide;
    int      inset;        // distance from the window edge
    int      y;
    int      petalRadius;
    int      petalOffset;
    COLORREF petalColour;
    COLORREF centreColour;
};

static std::vector<FlowerSpec> gFlowerSpecs;

// Randomised once (per app launch), not every repaint - otherwise the
// pattern would jitter every time the window redraws.
static void GenerateFlowerSpecs()
{
    struct Palette { COLORREF petal; COLORREF centre; };
    const COLORREF cream = kThemeCallMe.windowBg;
    const Palette palette[] = {
        { RGB(94,  156, 190), cream               }, // blue
        { RGB(232, 150, 178), RGB(237, 140, 44)   }, // pink + orange centre
        { RGB(130, 157, 108), cream               }, // green
    };
    const int paletteCount = 3;

    const int clientHeight = 688; // fixed window size (not resizable)
    const int minY = 34, maxY = clientHeight - 34;
    const int flowerCount = 12;

    gFlowerSpecs.clear();
    for (int i = 0; i < flowerCount; ++i)
    {
        FlowerSpec spec;
        spec.leftSide    = (rand() % 2) == 0;
        spec.inset       = 6 + rand() % 8;                  // 6-13px from the edge
        spec.y            = minY + rand() % (maxY - minY);
        spec.petalRadius = 5 + rand() % 3;                  // 5-7
        spec.petalOffset = spec.petalRadius - 1;

        const Palette& p = palette[rand() % paletteCount];
        spec.petalColour  = BlendColour(p.petal,  cream, 0.62); // soft, "a bit transparent"
        spec.centreColour = BlendColour(p.centre, cream, 0.75);

        gFlowerSpecs.push_back(spec);
    }
}

// ---------------------------------------------------------------------------
// Draws a simple 5-petal flower (five overlapping circles plus a centre
// dot) at the given point - an original vector shape, not an imported image.
// The pen always matches the fill colour, so no border can show even if
// NULL_PEN isn't honoured correctly on a particular display.
// ---------------------------------------------------------------------------

static void DrawFlowerAt(HDC dc, int cx, int cy, int petalRadius, int petalOffset,
                         COLORREF petalColour, COLORREF centreColour)
{
    HPEN    petalPen   = CreatePen(PS_SOLID, 1, petalColour);
    HBRUSH  petalBrush = CreateSolidBrush(petalColour);
    HGDIOBJ oldPen     = SelectObject(dc, petalPen);
    HGDIOBJ oldBrush   = SelectObject(dc, petalBrush);

    for (int i = 0; i < 5; ++i)
    {
        double angle = (-90.0 + i * 72.0) * 3.14159265358979 / 180.0;
        int px = cx + static_cast<int>(petalOffset * std::cos(angle));
        int py = cy + static_cast<int>(petalOffset * std::sin(angle));
        Ellipse(dc, px - petalRadius, py - petalRadius, px + petalRadius, py + petalRadius);
    }

    HPEN   centrePen   = CreatePen(PS_SOLID, 1, centreColour);
    HBRUSH centreBrush = CreateSolidBrush(centreColour);
    SelectObject(dc, centrePen);
    SelectObject(dc, centreBrush);
    int holeRadius = petalRadius / 2;
    if (holeRadius < 3) holeRadius = 3;
    Ellipse(dc, cx - holeRadius, cy - holeRadius, cx + holeRadius, cy + holeRadius);

    SelectObject(dc, oldBrush);
    SelectObject(dc, oldPen);
    DeleteObject(petalBrush);
    DeleteObject(petalPen);
    DeleteObject(centreBrush);
    DeleteObject(centrePen);
}

// ---------------------------------------------------------------------------
// Apply a theme: rebuild the background brushes and force a full repaint.
// ---------------------------------------------------------------------------

static void SetActiveTheme(const ThemeColours& theme, int themeId)
{
    gTheme = theme;
    gActiveThemeId = themeId;

    if (gWindowBgBrush) DeleteObject(gWindowBgBrush);
    if (gEditBgBrush)   DeleteObject(gEditBgBrush);
    gWindowBgBrush = CreateSolidBrush(gTheme.windowBg);
    gEditBgBrush   = CreateSolidBrush(gTheme.editBg);

    if (gMainWnd)
    {
        HMENU menu = GetMenu(gMainWnd);
        if (menu)
        {
            CheckMenuRadioItem(menu, IDM_THEME_DEFAULT, IDM_THEME_CALLME,
                              IDM_THEME_DEFAULT + themeId, MF_BYCOMMAND);
        }
        InvalidateRect(gMainWnd, NULL, TRUE);
        InvalidateRect(gMeterCtl, NULL, TRUE);
    }
}

// ---------------------------------------------------------------------------
// Data breach check (Have I Been Pwned "Pwned Passwords" API)
//
// This never sends the password, or even its full hash, anywhere. The
// password is hashed locally with SHA-1 (Windows' own CryptoAPI). Only the
// first 5 hex characters of that hash are sent to the server - a "k-anonymity"
// lookup. The server sends back every breached hash suffix that starts with
// those 5 characters, and the match is checked locally. No API key, no
// account, and the real password never leaves this computer.
// ---------------------------------------------------------------------------

static bool Sha1HashHex(const std::wstring& input, std::wstring& outHex)
{
    outHex.clear();

    int utf8Len = WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, NULL, 0, NULL, NULL);
    if (utf8Len <= 0) return false;
    std::string utf8(static_cast<size_t>(utf8Len) - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, &utf8[0], utf8Len, NULL, NULL);

    bool ok = false;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;

    if (CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        if (CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash))
        {
            if (CryptHashData(hHash, reinterpret_cast<const BYTE*>(utf8.data()),
                              static_cast<DWORD>(utf8.size()), 0))
            {
                BYTE digest[20];
                DWORD digestLen = sizeof(digest);
                if (CryptGetHashParam(hHash, HP_HASHVAL, digest, &digestLen, 0))
                {
                    wchar_t hex[41];
                    for (int i = 0; i < 20; ++i)
                        swprintf_s(hex + i * 2, 3, L"%02X", digest[i]);
                    outHex = hex;
                    ok = true;
                }
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }

    return ok;
}

// Downloads the list of breached hash suffixes that share the given 5-char
// prefix. Returns false (with errorMsg set) on any network failure.
static bool QueryPwnedRange(const std::wstring& prefix5, std::wstring& body, std::wstring& errorMsg)
{
    body.clear();
    errorMsg.clear();

    HINTERNET hSession = WinHttpOpen(L"PasswordAuditor/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession)
    {
        errorMsg = L"Could not start a network session.";
        return false;
    }

    // Keep this snappy: a school network that blocks the request should
    // fail fast rather than freezing the app for a long time.
    WinHttpSetTimeouts(hSession, 6000, 6000, 6000, 6000);

    HINTERNET hConnect = WinHttpConnect(hSession, L"api.pwnedpasswords.com",
                                        INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect)
    {
        errorMsg = L"Could not reach api.pwnedpasswords.com.";
        WinHttpCloseHandle(hSession);
        return false;
    }

    std::wstring path = L"/range/" + prefix5;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path.c_str(), NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest)
    {
        errorMsg = L"Could not build the request.";
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    bool ok = false;
    BOOL sent = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                   WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    BOOL received = sent && WinHttpReceiveResponse(hRequest, NULL);

    if (received)
    {
        std::string raw;
        for (;;)
        {
            DWORD available = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &available) || available == 0) break;

            std::vector<char> buffer(available);
            DWORD bytesRead = 0;
            if (!WinHttpReadData(hRequest, buffer.data(), available, &bytesRead)) break;
            raw.append(buffer.data(), bytesRead);
        }

        int wideLen = MultiByteToWideChar(CP_UTF8, 0, raw.c_str(), static_cast<int>(raw.size()), NULL, 0);
        if (wideLen > 0)
        {
            body.resize(wideLen);
            MultiByteToWideChar(CP_UTF8, 0, raw.c_str(), static_cast<int>(raw.size()), &body[0], wideLen);
        }
        ok = true;
    }
    else
    {
        errorMsg = L"No response from the breach-check server. Check the internet "
                   L"connection, or the network may be blocking this request.";
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return ok;
}

// The API returns lines of "SUFFIX:COUNT". Look for our suffix among them.
static bool FindSuffixInResponse(const std::wstring& body, const std::wstring& suffix, long long& count)
{
    count = 0;
    std::wistringstream stream(body);
    std::wstring line;

    while (std::getline(stream, line))
    {
        if (!line.empty() && line.back() == L'\r') line.pop_back();

        size_t colon = line.find(L':');
        if (colon == std::wstring::npos) continue;

        if (_wcsicmp(line.substr(0, colon).c_str(), suffix.c_str()) == 0)
        {
            count = _wtoi64(line.substr(colon + 1).c_str());
            return true;
        }
    }
    return false;
}

// Adds thousands separators (1653201 -> "1,653,201") for readability.
static std::wstring FormatCount(long long value)
{
    std::wstring digits = std::to_wstring(value);
    std::wstring result;
    int sinceComma = 0;
    for (auto it = digits.rbegin(); it != digits.rend(); ++it)
    {
        result.insert(result.begin(), *it);
        if (++sinceComma % 3 == 0 && std::next(it) != digits.rend())
            result.insert(result.begin(), L',');
    }
    return result;
}

static void RunBreachCheck()
{
    wchar_t buffer[129];
    GetWindowTextW(gPasswordEdit, buffer, 129);
    std::wstring password(buffer);

    if (password.empty())
    {
        MessageBoxW(gMainWnd, L"Enter a password first, then check it for breaches.",
                    L"Nothing to Check", MB_OK | MB_ICONINFORMATION);
        return;
    }

    std::wstring fullHash;
    if (!Sha1HashHex(password, fullHash) || fullHash.size() != 40)
    {
        MessageBoxW(gMainWnd, L"Could not hash the password locally.",
                    L"Error", MB_OK | MB_ICONERROR);
        return;
    }

    std::wstring prefix = fullHash.substr(0, 5);
    std::wstring suffix = fullHash.substr(5);

    HCURSOR oldCursor = SetCursor(LoadCursorW(NULL, IDC_WAIT));

    std::wstring body, errorMsg;
    bool success = QueryPwnedRange(prefix, body, errorMsg);

    SetCursor(oldCursor);

    if (!success)
    {
        MessageBoxW(gMainWnd, errorMsg.c_str(), L"Could Not Check Online", MB_OK | MB_ICONWARNING);
        return;
    }

    long long breachCount = 0;
    bool found = FindSuffixInResponse(body, suffix, breachCount);

    if (found)
    {
        // A corrected 4-tier scale (the original 3-tier idea left a gap
        // between 10,000 and 100,000 undefined).
        std::wstring severity;
        UINT          icon;
        if      (breachCount < 100)     { severity = L"LOW";      icon = MB_ICONINFORMATION; }
        else if (breachCount < 10000)   { severity = L"MEDIUM";   icon = MB_ICONWARNING;     }
        else if (breachCount < 100000)  { severity = L"HIGH";     icon = MB_ICONWARNING;     }
        else                             { severity = L"CRITICAL"; icon = MB_ICONERROR;       }

        std::wstringstream msg;
        msg << L"Severity: " << severity << L"\r\n\r\n"
            << L"This exact password has appeared " << FormatCount(breachCount)
            << (breachCount == 1 ? L" time" : L" times") << L" in known data breaches.\r\n\r\n"
            << L"It is in circulation on hacker password lists and will be tried "
               L"automatically against your accounts. Change it now, and anywhere "
               L"else you have reused it.";
        MessageBoxW(gMainWnd, msg.str().c_str(), L"Found in Breach Data", MB_OK | icon);
    }
    else
    {
        MessageBoxW(gMainWnd,
                    L"Good news: this exact password was not found in the breach "
                    L"database checked.\r\n\r\nThis does not guarantee it is strong, "
                    L"only that it has not previously leaked. Use Audit Password for "
                    L"a full strength check.",
                    L"Not Found in Breach Data", MB_OK | MB_ICONINFORMATION);
    }
}

// ---------------------------------------------------------------------------
// Save the most recent report to a .txt file the user picks
// ---------------------------------------------------------------------------

static void SaveReportToFile(const std::wstring& reportText)
{
    if (reportText.empty())
    {
        MessageBoxW(gMainWnd,
                    L"Run an audit first, then Save Report will save its results.",
                    L"Nothing to Save",
                    MB_OK | MB_ICONINFORMATION);
        return;
    }

    wchar_t fileName[MAX_PATH] = L"PasswordAuditReport.txt";

    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = gMainWnd;
    ofn.lpstrFilter = L"Text File (*.txt)\0*.txt\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile   = fileName;
    ofn.nMaxFile    = MAX_PATH;
    ofn.lpstrDefExt = L"txt";
    ofn.Flags       = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;

    if (!GetSaveFileNameW(&ofn))
        return; // user cancelled

    HANDLE file = CreateFileW(fileName, GENERIC_WRITE, 0, NULL,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (file == INVALID_HANDLE_VALUE)
    {
        MessageBoxW(gMainWnd, L"Could not save the file.", L"Save Failed", MB_OK | MB_ICONERROR);
        return;
    }

    // Write as UTF-8 with a BOM so Notepad and Word display it correctly.
    int needed = WideCharToMultiByte(CP_UTF8, 0, reportText.c_str(), -1, NULL, 0, NULL, NULL);
    std::string utf8;
    if (needed > 0)
    {
        utf8.resize(static_cast<size_t>(needed) - 1);
        WideCharToMultiByte(CP_UTF8, 0, reportText.c_str(), -1, &utf8[0], needed, NULL, NULL);
    }

    const unsigned char bom[] = { 0xEF, 0xBB, 0xBF };
    DWORD written = 0;
    WriteFile(file, bom, sizeof(bom), &written, NULL);
    WriteFile(file, utf8.data(), static_cast<DWORD>(utf8.size()), &written, NULL);
    CloseHandle(file);

    MessageBoxW(gMainWnd, L"Report saved.", L"Saved", MB_OK | MB_ICONINFORMATION);
}

// ---------------------------------------------------------------------------
// The built-in scrollbar normally shifts the visible pixels and only
// redraws the newly revealed strip. On some remote/virtual displays that
// partial redraw doesn't clear properly, leaving old text visible behind
// the new scroll position. Subclassing the control lets us force a full,
// non-optimized repaint after anything that could have scrolled it.
// ---------------------------------------------------------------------------

static WNDPROC gOldEditProc = NULL;

static LRESULT CALLBACK OutputEditSubclassProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    LRESULT result = CallWindowProcW(gOldEditProc, hwnd, msg, wParam, lParam);

    if (msg == WM_VSCROLL || msg == WM_HSCROLL || msg == WM_MOUSEWHEEL ||
        msg == WM_KEYDOWN  || msg == WM_SETTEXT)
    {
        InvalidateRect(hwnd, NULL, TRUE);
        UpdateWindow(hwnd);
    }

    return result;
}

static void SubclassOutputEdit(HWND edit)
{
    gOldEditProc = reinterpret_cast<WNDPROC>(
        SetWindowLongPtrW(edit, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(OutputEditSubclassProc)));
}

// ---------------------------------------------------------------------------
// Replace the report text by destroying and recreating the output control.
// A brand-new window has never been painted, so there is no old content for
// it to ghost behind the new text - this removes the redraw bug entirely
// rather than working around it.
// ---------------------------------------------------------------------------

static void SetOutputText(const std::wstring& text)
{
    RECT rc;
    GetWindowRect(gOutputEdit, &rc);
    POINT topLeft = { rc.left, rc.top };
    ScreenToClient(gMainWnd, &topLeft);
    int width  = rc.right  - rc.left;
    int height = rc.bottom - rc.top;

    DestroyWindow(gOutputEdit);

    gOutputEdit = CreateWindowExW(
        WS_EX_CLIENTEDGE, L"EDIT", text.c_str(),
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_TABSTOP |
        ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
        topLeft.x, topLeft.y, width, height,
        gMainWnd, (HMENU)IDC_OUTPUT_EDIT, NULL, NULL);
    SendMessageW(gOutputEdit, WM_SETFONT, (WPARAM)gMonoFont, TRUE);
    SubclassOutputEdit(gOutputEdit);
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

    gMeterScore = result.score;
    InvalidateRect(gMeterCtl, NULL, TRUE);

    gLastReportText = BuildReport(password, result);
    gHasResult = true;

    SetOutputText(gLastReportText);
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
        GenerateFlowerSpecs();

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
            20, 152, 150, 34,
            hwnd, (HMENU)IDC_ANALYSE_BTN, NULL, NULL);
        SendMessageW(analyseButton, WM_SETFONT, (WPARAM)gUiFont, TRUE);

        HWND generateButton = CreateWindowExW(
            0, L"BUTTON", L"Suggest a Strong Passphrase",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            180, 152, 220, 34,
            hwnd, (HMENU)IDC_GENERATE_BTN, NULL, NULL);
        SendMessageW(generateButton, WM_SETFONT, (WPARAM)gUiFont, TRUE);

        HWND saveButton = CreateWindowExW(
            0, L"BUTTON", L"Save Report",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            410, 152, 140, 34,
            hwnd, (HMENU)IDC_SAVE_BTN, NULL, NULL);
        SendMessageW(saveButton, WM_SETFONT, (WPARAM)gUiFont, TRUE);

        HWND clearButton = CreateWindowExW(
            0, L"BUTTON", L"Clear",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            560, 152, 100, 34,
            hwnd, (HMENU)IDC_CLEAR_BTN, NULL, NULL);
        SendMessageW(clearButton, WM_SETFONT, (WPARAM)gUiFont, TRUE);

        HWND breachButton = CreateWindowExW(
            0, L"BUTTON", L"Check for Data Breaches (online, no password sent)",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            20, 192, 680, 34,
            hwnd, (HMENU)IDC_BREACH_BTN, NULL, NULL);
        SendMessageW(breachButton, WM_SETFONT, (WPARAM)gUiFont, TRUE);

        gScoreLabel = CreateWindowExW(
            0, L"STATIC", L"Score: -- / 100",
            WS_CHILD | WS_VISIBLE,
            20, 240, 680, 28,
            hwnd, (HMENU)IDC_SCORE_LABEL, NULL, NULL);
        SendMessageW(gScoreLabel, WM_SETFONT, (WPARAM)gScoreFont, TRUE);

        // Owner-drawn strength meter: a filled bar whose width and colour
        // reflect the score. Actual drawing happens in WM_DRAWITEM.
        gMeterCtl = CreateWindowExW(
            WS_EX_CLIENTEDGE, L"STATIC", L"",
            WS_CHILD | WS_VISIBLE | SS_OWNERDRAW,
            20, 272, 680, 20,
            hwnd, (HMENU)IDC_METER, NULL, NULL);

        gOutputEdit = CreateWindowExW(
            WS_EX_CLIENTEDGE, L"EDIT",
            L"Enter a password above and press Audit Password.\r\n\r\n"
            L"Nothing you type is saved, logged or sent anywhere. All analysis\r\n"
            L"happens on this computer.",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_TABSTOP |
            ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
            20, 300, 680, 368,
            hwnd, (HMENU)IDC_OUTPUT_EDIT, NULL, NULL);
        SendMessageW(gOutputEdit, WM_SETFONT, (WPARAM)gMonoFont, TRUE);
        SubclassOutputEdit(gOutputEdit);

        return 0;
    }

    case WM_DRAWITEM:
    {
        LPDRAWITEMSTRUCT dis = reinterpret_cast<LPDRAWITEMSTRUCT>(lParam);
        if (dis->CtlID == IDC_METER)
        {
            RECT rc = dis->rcItem;

            HBRUSH background = CreateSolidBrush(gTheme.meterEmptyBg);
            FillRect(dis->hDC, &rc, background);
            DeleteObject(background);

            int fullWidth = rc.right - rc.left;
            int fillWidth = static_cast<int>(fullWidth * (gMeterScore / 100.0));
            if (fillWidth > 0)
            {
                RECT fillRect = rc;
                fillRect.right = rc.left + fillWidth;
                HBRUSH fillBrush = CreateSolidBrush(gScoreColour);
                FillRect(dis->hDC, &fillRect, fillBrush);
                DeleteObject(fillBrush);
            }

            HPEN borderPen = CreatePen(PS_SOLID, 1, gTheme.meterBorder);
            HGDIOBJ oldPen = SelectObject(dis->hDC, borderPen);
            HGDIOBJ oldBrush = SelectObject(dis->hDC, GetStockObject(NULL_BRUSH));
            Rectangle(dis->hDC, rc.left, rc.top, rc.right, rc.bottom);
            SelectObject(dis->hDC, oldBrush);
            SelectObject(dis->hDC, oldPen);
            DeleteObject(borderPen);

            return TRUE;
        }
        break;
    }

    case WM_ERASEBKGND:
    {
        HDC dc = (HDC)wParam;
        RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect(dc, &rc, gWindowBgBrush);

        // Cream Pastel theme only: scatter small flowers down the empty
        // 20px margins on each side, where no control ever sits, so
        // nothing can overlap or fight for repaint with them. Positions
        // are randomised once at launch (see GenerateFlowerSpecs).
        if (gActiveThemeId == 3)
        {
            RECT clientRc;
            GetClientRect(hwnd, &clientRc);

            for (const FlowerSpec& spec : gFlowerSpecs)
            {
                int x = spec.leftSide ? spec.inset : (clientRc.right - spec.inset);
                DrawFlowerAt(dc, x, spec.y, spec.petalRadius, spec.petalOffset,
                            spec.petalColour, spec.centreColour);
            }
        }

        return 1;
    }

    case WM_CTLCOLORSTATIC:
    {
        HDC  dc      = (HDC)wParam;
        HWND control = (HWND)lParam;

        SetBkMode(dc, TRANSPARENT);

        if (control == gScoreLabel)
            SetTextColor(dc, gScoreColour);
        else
            SetTextColor(dc, gTheme.textColour);

        return (LRESULT)gWindowBgBrush;
    }

    case WM_CTLCOLOREDIT:
    {
        HDC dc = (HDC)wParam;
        SetTextColor(dc, gTheme.editText);
        SetBkColor(dc, gTheme.editBg);
        return (LRESULT)gEditBgBrush;
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

        case IDC_SAVE_BTN:
            SaveReportToFile(gLastReportText);
            return 0;

        case IDC_BREACH_BTN:
            RunBreachCheck();
            return 0;

        case IDM_THEME_DEFAULT:
            SetActiveTheme(kThemeDefault, 0);
            return 0;

        case IDM_THEME_WARM:
            SetActiveTheme(kThemeWarm, 1);
            return 0;

        case IDM_THEME_DARK:
            SetActiveTheme(kThemeDark, 2);
            return 0;

        case IDM_THEME_CALLME:
            SetActiveTheme(kThemeCallMe, 3);
            return 0;

        case IDM_SHOW_DAD:
            ShowDadPopup();
            return 0;

        case IDM_SHOW_COMPARE:
            ShowComparePopup();
            return 0;

        case IDM_SHOW_REUSE:
            ShowReusePopup();
            return 0;

        case IDC_CLEAR_BTN:
            SetWindowTextW(gPasswordEdit, L"");
            SetWindowTextW(gScoreLabel, L"Score: -- / 100");
            gScoreColour = RGB(70, 70, 70);
            InvalidateRect(gScoreLabel, NULL, TRUE);
            gMeterScore = 0;
            InvalidateRect(gMeterCtl, NULL, TRUE);
            gLastReportText.clear();
            gHasResult = false;
            SetOutputText(
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

    // Create theme brushes before any window/control exists, so the very
    // first paint (which happens during CreateWindowExW itself) already
    // has a valid background brush to use.
    SetActiveTheme(kThemeDefault, 0);

    HMENU themeMenu = CreatePopupMenu();
    AppendMenuW(themeMenu, MF_STRING, IDM_THEME_DEFAULT, L"Default");
    AppendMenuW(themeMenu, MF_STRING, IDM_THEME_WARM,    L"Warm (Beige / Baby Blue / Brown)");
    AppendMenuW(themeMenu, MF_STRING, IDM_THEME_DARK,    L"Dark");
    AppendMenuW(themeMenu, MF_STRING, IDM_THEME_CALLME,  L"Cream Pastel (Pink / Teal / Mustard)");
    CheckMenuRadioItem(themeMenu, IDM_THEME_DEFAULT, IDM_THEME_CALLME, IDM_THEME_DEFAULT, MF_BYCOMMAND);

    HMENU menuBar = CreateMenu();
    AppendMenuW(menuBar, MF_POPUP, (UINT_PTR)themeMenu, L"Theme");

    HMENU funMenu = CreatePopupMenu();
    AppendMenuW(funMenu, MF_STRING, IDM_SHOW_DAD, L"Say Hi to Dad");
    AppendMenuW(menuBar, MF_POPUP, (UINT_PTR)funMenu, L"Kalindu");

    HMENU toolsMenu = CreatePopupMenu();
    AppendMenuW(toolsMenu, MF_STRING, IDM_SHOW_COMPARE, L"Compare Passwords");
    AppendMenuW(toolsMenu, MF_STRING, IDM_SHOW_REUSE,   L"Password Reuse Risk");
    AppendMenuW(menuBar, MF_POPUP, (UINT_PTR)toolsMenu, L"Tools");

    RECT desired = { 0, 0, 720, 688 };
    AdjustWindowRect(&desired, WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_THICKFRAME, TRUE);

    gMainWnd = CreateWindowExW(
        0,
        CLASS_NAME,
        L"Password Strength Auditor",
        WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_THICKFRAME,
        CW_USEDEFAULT, CW_USEDEFAULT,
        desired.right - desired.left,
        desired.bottom - desired.top,
        NULL, menuBar, hInstance, NULL);

    if (gMainWnd == NULL)
    {
        MessageBoxW(NULL, L"Failed to create the application window.",
                    L"Startup Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    // Now that the window exists, let the theme system sync the menu
    // checkmark against it too.
    SetActiveTheme(kThemeDefault, 0);

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
