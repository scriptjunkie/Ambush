/*
 * Copyright (c) 2004-2005 Sergey Lyubka <valenok@gmail.com>
 * All rights reserved
 *
 * "THE BEER-WARE LICENSE" (Revision 42):
 * Sergey Lyubka wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.
 */

/* Modified for wchar_t support by scriptjunkie */

#ifndef WSLRE_HEADER_DEFINED
#define	WSLRE_HEADER_DEFINED

/*
 * Compiled regular expression
 */
struct wslre {
	wchar_t	code[256];
	wchar_t	data[256];
	int		code_size;
	int		data_size;
	int		num_caps;	/* Number of bracket pairs	*/
	int		anchored;	/* Must match from string start	*/
	const wchar_t	*err_str;	/* Error string			*/
};

/*
 * Captured substring
 */
struct wcap {
	const wchar_t	*ptr;		/* Pointer to the substring	*/
	int		len;		/* Substring length		*/
};

/*
 * Compile regular expression. If success, 1 is returned.
 * If error, 0 is returned and slre.err_str points to the error message. 
 */
int wslre_compile(struct wslre *, const wchar_t *re);

/*
 * Return 1 if match, 0 if no match. 
 * If `captured_substrings' array is not NULL, then it is filled with the
 * values of captured substrings. captured_substrings[0] element is always
 * a full matched substring. The round bracket captures start from
 * captured_substrings[1].
 * It is assumed that the size of captured_substrings array is enough to
 * hold all captures. The caller function must make sure it is! So, the
 * array_size = number_of_round_bracket_pairs + 1
 */
int wslre_match(const struct wslre *, const wchar_t *buf, int buf_len,
	struct wcap *captured_substrings);

#endif /* SLRE_HEADER_DEFINED */