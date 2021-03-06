// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"
#include "ZeekString.h"

#include <algorithm>
#include <iostream>
#include <ctype.h>

#include "Val.h"
#include "ID.h"
#include "Reporter.h"
#include "util.h"

#ifdef DEBUG
#define DEBUG_STR(msg) DBG_LOG(zeek::DBG_STRING, msg)
#else
#define DEBUG_STR(msg)
#endif

namespace zeek {

constexpr int String::EXPANDED_STRING;
constexpr int String::BRO_STRING_LITERAL;

// This constructor forces the user to specify arg_final_NUL.  When str
// is a *normal* NUL-terminated string, make arg_n == strlen(str) and
// arg_final_NUL == 1; when str is a sequence of n bytes, make
// arg_final_NUL == 0.

String::String(bool arg_final_NUL, byte_vec str, int arg_n)
	{
	b = str;
	n = arg_n;
	final_NUL = arg_final_NUL;
	use_free_to_delete = false;
	}

String::String(const u_char* str, int arg_n, bool add_NUL) : String()
	{
	Set(str, arg_n, add_NUL);
	}

String::String(const char* str) : String()
	{
	Set(str);
	}

String::String(const std::string &str) : String()
	{
	Set(str);
	}

String::String(const String& bs) : String()
	{
	*this = bs;
	}

String::String()
	{
	b = nullptr;
	n = 0;
	final_NUL = false;
	use_free_to_delete = false;
	}

void String::Reset()
	{
	if ( use_free_to_delete )
		free(b);
	else
		delete [] b;

	b = nullptr;
	n = 0;
	final_NUL = false;
	use_free_to_delete = false;
	}

const String& String::operator=(const String &bs)
	{
	Reset();
	n = bs.n;
	b = new u_char[n+1];

	memcpy(b, bs.b, n);
	b[n] = '\0';

	final_NUL = true;
	use_free_to_delete = false;
	return *this;
	}

bool String::operator==(const String &bs) const
	{
	return Bstr_eq(this, &bs);
	}

bool String::operator<(const String &bs) const
	{
	return Bstr_cmp(this, &bs) < 0;
	}

void String::Adopt(byte_vec bytes, int len)
	{
	Reset();

	b = bytes;

	// Check if the string ends with a NUL.  If so, mark it as having
	// a final NUL and adjust the length accordingly.
	final_NUL = (b[len-1] == '\0');
	n = len - final_NUL;
	}

void String::Set(const u_char* str, int len, bool add_NUL)
	{
	Reset();

	n = len;
	b = new u_char[add_NUL ? n + 1 : n];
	memcpy(b, str, n);
	final_NUL = add_NUL;

	if ( add_NUL )
		b[n] = 0;

	use_free_to_delete = false;
	}

void String::Set(const char* str)
	{
	Reset();

	if ( str )
		{
		n = strlen(str);
		b = new u_char[n+1];
		memcpy(b, str, n+1);
		final_NUL = true;
		use_free_to_delete = false;
		}
	}

void String::Set(const std::string& str)
	{
	Reset();

	n = str.size();
	b = new u_char[n+1];
	memcpy(b, str.c_str(), n+1);
	final_NUL = true;
	use_free_to_delete = false;
	}

void String::Set(const String& str)
	{
	*this = str;
	}

const char* String::CheckString() const
	{
	void *nulTerm;
	if ( n == 0 )
		return "";

	nulTerm = memchr(b, '\0', n + final_NUL);
	if ( nulTerm != &b[n] )
		{
		// Either an embedded NUL, or no final NUL.
		char* exp_s = Render();
		if ( nulTerm )
			reporter->Error("string with embedded NUL: \"%s\"", exp_s);
		else
			reporter->Error("string without NUL terminator: \"%s\"", exp_s);

		delete [] exp_s;
		return "<string-with-NUL>";
		}

	return (const char*) b;
	}

char* String::Render(int format, int* len) const
	{
	// Maxmimum character expansion is as \xHH, so a factor of 4.
	char* s = new char[n*4 + 1];	// +1 is for final '\0'
	char* sp = s;
	int tmp_len;

	for ( int i = 0; i < n; ++i )
		{
		if ( b[i] == '\\' && (format & ESC_ESC) )
			{
			*sp++ = '\\'; *sp++ = '\\';
			}

		else if ( (b[i] == '\'' || b[i] == '"') && (format & ESC_QUOT) )
			{
			*sp++ = '\\'; *sp++ = b[i];
			}

		else if ( (b[i] < ' ' || b[i] > 126) && (format & ESC_HEX) )
			{
			char hex_fmt[16];

			*sp++ = '\\'; *sp++ = 'x';
			sprintf(hex_fmt, "%02x", b[i]);
			*sp++ = hex_fmt[0]; *sp++ = hex_fmt[1];
			}

		else if ( (b[i] < ' ' || b[i] > 126) && (format & ESC_DOT) )
			{
			*sp++ = '.';
			}

		else
			{
			*sp++ = b[i];
			}
		}

	*sp++ = '\0';	// NUL-terminate.
	tmp_len = sp - s;

	if ( (format & ESC_SER) )
		{
		char* result = new char[tmp_len + 16];
		snprintf(result, tmp_len + 16, "%u ", tmp_len - 1);
		tmp_len += strlen(result);
		memcpy(result + strlen(result), s, sp - s);
		delete [] s;
		s = result;
		}

	if ( len )
		*len = tmp_len;

	return s;
	}

std::ostream& String::Render(std::ostream &os, int format) const
	{
	char* tmp = Render(format);
	os << tmp;
	delete [] tmp;
	return os;
	}

std::istream& String::Read(std::istream &is, int format)
	{
	if ( (format & String::ESC_SER) )
		{
		int len;
		is >> len;	// Get the length of the string

		char c;
		is.read(&c, 1);	// Eat single whitespace

		char* buf = new char[len+1];
		is.read(buf, len);
		buf[len] = '\0';	// NUL-terminate just for safety

		Adopt((u_char*) buf, len+1);
		}
	else
		{
		std::string str;
		is >> str;
		Set(str);
		}

	return is;
	}

void String::ToUpper()
	{
	for ( int i = 0; i < n; ++i )
		if ( islower(b[i]) )
			b[i] = toupper(b[i]);
	}

unsigned int String::MemoryAllocation() const
	{
	return padded_sizeof(*this) + util::pad_size(n + final_NUL);
	}

String* String::GetSubstring(int start, int len) const
	{
	// This code used to live in zeek.bif's sub_bytes() routine.
	if ( start < 0 || start > n )
		return nullptr;

	if ( len < 0 || len > n - start )
		len = n - start;

	return new String(&b[start], len, true);
	}

int String::FindSubstring(const String* s) const
	{
	return util::strstr_n(n, b, s->Len(), s->Bytes());
	}

String::Vec* String::Split(const String::IdxVec& indices) const
	{
	size_t i;

	if ( indices.empty() )
		return nullptr;

	// Copy input, ensuring space for "0":
	IdxVec idx(1 + indices.size());

	idx[0] = 0;
	idx.insert(idx.end(), indices.begin(), indices.end());

	// Sanity checks.
	for ( i = 0; i < idx.size(); ++i )
		if ( idx[i] >= n || idx[i] < 0 )
			idx[i] = 0;

	// Sort it:
	sort(idx.begin(), idx.end());

	// Shuffle vector so duplicate entries are used only once:
	IdxVecIt end = unique(idx.begin(), idx.end());

	// Each element in idx is now the start index of a new
	// substring, and we know that all indices are within [0, n].
	//
	Vec* result = new Vec();
	int last_idx = -1;
	int next_idx;
	i = 0;

	for ( IdxVecIt it = idx.begin(); it != end; ++it, ++i )
		{
		int len = (it + 1 == end) ? -1 : idx[i + 1] - idx[i];
		result->push_back(GetSubstring(idx[i], len));
		}

	return result;
	}

VectorVal* String:: VecToPolicy(Vec* vec)
	{
	auto result = make_intrusive<VectorVal>(id::string_vec);

	for ( unsigned int i = 0; i < vec->size(); ++i )
		{
		String* string = (*vec)[i];
		auto val = make_intrusive<StringVal>(string->Len(),
		                                     (const char*) string->Bytes());
		result->Assign(i+1, std::move(val));
		}

	return result.release();
	}

String::Vec* String::VecFromPolicy(VectorVal* vec)
	{
	Vec* result = new Vec();

	// VectorVals start at index 1!
	for ( unsigned int i = 1; i <= vec->Size(); ++i )
		{
		const auto& v = vec->At(i);	// get the RecordVal
		if ( ! v )
			continue;

		String* string = new String(*(v->AsString()));
		result->push_back(string);
		}

	return result;
	}

char* String::VecToString(const Vec* vec)
	{
	std::string result("[");

	for ( String::VecCIt it = vec->begin(); it != vec->end(); ++it )
		{
		result += (*it)->CheckString();
		result += ",";
		}

	result += "]";

	return strdup(result.c_str());
	}

bool StringLenCmp::operator()(String * const& bst1,
				 String * const& bst2)
	{
	return _increasing ? (bst1->Len() < bst2->Len()) :
				(bst1->Len() > bst2->Len());
	}

std::ostream& operator<<(std::ostream& os, const String& bs)
	{
	char* tmp = bs.Render(String::EXPANDED_STRING);
	os << tmp;
	delete [] tmp;
	return os;
	}

int Bstr_eq(const String* s1, const String* s2)
	{
	if ( s1->Len() != s2->Len() )
		return 0;

	if ( ! s1->Bytes() || ! s2->Bytes() )
		// memcmp() arguments should never be null, so help avoid that
		return s1->Bytes() == s2->Bytes();

	return memcmp(s1->Bytes(), s2->Bytes(), s1->Len()) == 0;
	}

int Bstr_cmp(const String* s1, const String* s2)
	{
	int n = std::min(s1->Len(), s2->Len());
	// memcmp() arguments should never be null, so help avoid that
	// (assuming that we only ever have null pointers when lengths are zero).
	int cmp = n == 0 ? 0 : memcmp(s1->Bytes(), s2->Bytes(), n);

	if ( cmp || s1->Len() == s2->Len() )
		return cmp;

	// Compared equal, but one was shorter than the other.  Treat
	// it as less than the other.
	if ( s1->Len() < s2->Len() )
		return -1;
	else
		return 1;
	}

String* concatenate(std::vector<data_chunk_t>& v)
	{
	int n = v.size();
	int len = 0;
	int i;
	for ( i = 0; i < n; ++i )
		len += v[i].length;

	char* data = new char[len+1];

	char* b = data;
	for ( i = 0; i < n; ++i )
		{
		memcpy(b, v[i].data, v[i].length);
		b += v[i].length;
		}

	*b = '\0';

	return new String(true, (byte_vec) data, len);
	}

String* concatenate(String::CVec& v)
	{
	int n = v.size();
	int len = 0;
	int i;
	for ( i = 0; i < n; ++i )
		len += v[i]->Len();

	char* data = new char[len+1];

	char* b = data;
	for ( i = 0; i < n; ++i )
		{
		memcpy(b, v[i]->Bytes(), v[i]->Len());
		b += v[i]->Len();
		}
	*b = '\0';

	return new String(true, (byte_vec) data, len);
	}

String* concatenate(String::Vec& v)
	{
	String::CVec cv;

	for ( String::VecIt it = v.begin(); it != v.end(); ++it )
		cv.push_back(*it);

	return concatenate(cv);
	}

void delete_strings(std::vector<const String*>& v)
	{
	for ( auto& elem : v )
		delete elem;
	v.clear();
	}

} // namespace zeek
