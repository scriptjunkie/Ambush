/*
 * Copyright (c) 2004-2005 Sergey Lyubka <valenok@gmail.com>
 * All rights reserved
 *
 * "THE BEER-WARE LICENSE" (Revision 42):
 * Sergey Lyubka wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.


 modified for wchar_t by scriptjunkie
 Sergey, if I meet you, I will buy you a beer.
 */

#include <stdio.h>
#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "wslre.h"

enum {END, BRANCH, ANY, EXACT, ANYOF, ANYBUT, OPEN, CLOSE, BOL, EOL,
	STAR, PLUS, STARQ, PLUSQ, QUEST, SPACE, NONSPACE, DIGIT};

static const wchar_t *meta_wchars = L"|.^$*+?()[\\";

static void
set_jump_offset(struct wslre *r, int pc, int offset)
{
	assert(offset < r->code_size);

	if (r->code_size - offset > 0xff) {
		r->err_str = L"Jump offset is too big";
	} else {
		r->code[pc] = (wchar_t) (r->code_size - offset);
	}
}

static void
emit(struct wslre *r, int code)
{
	if (r->code_size >= (int) (sizeof(r->code) / sizeof(r->code[0])))
		r->err_str = L"RE is too long (code overflow)";
	else
		r->code[r->code_size++] = (wchar_t) code;
}

static void
store_char_in_data(struct wslre *r, int ch)
{
	if (r->data_size >= (int) sizeof(r->data) / sizeof(r->data[0]))
		r->err_str = L"RE is too long (data overflow)";
	else
		r->data[r->data_size++] = ch;
}

static const wchar_t * wstrchr(const wchar_t * chars, wchar_t ch){
	for(size_t i = 0; chars[i] != 0; i++)
		if(chars[i] == ch)
			return chars + i;
	return NULL;
}

static void
exact(struct wslre *r, const wchar_t **re)
{
	int	old_data_size = r->data_size;

	while (**re != '\0' && (wstrchr(meta_wchars, **re)) == NULL)
		store_char_in_data(r, *(*re)++);

	emit(r, EXACT);
	emit(r, old_data_size);
	emit(r, r->data_size - old_data_size);
}

static int
get_escape_char(const wchar_t **re)
{
	int	res;

	switch (*(*re)++) {
	case 'n':	res = '\n';		break;
	case 'r':	res = '\r';		break;
	case 't':	res = '\t';		break;
	case '0':	res = 0;		break;
	case 'S':	res = NONSPACE << 16;	break;
	case 's':	res = SPACE << 16;	break;
	case 'd':	res = DIGIT << 16;	break;
	default:	res = (*re)[-1];	break;
	}

	return (res);
}

static void
anyof(struct wslre *r, const wchar_t **re)
{
	int	esc, old_data_size = r->data_size, op = ANYOF;

	if (**re == '^') {
		op = ANYBUT;
		(*re)++;
	}

	while (**re != '\0')

		switch (*(*re)++) {
		case ']':
			emit(r, op);
			emit(r, old_data_size);
			emit(r, r->data_size - old_data_size);
			return;
			/* NOTREACHED */
			break;
		case '\\':
			esc = get_escape_char(re);
			if ((esc & 0xff) == 0) {
				store_char_in_data(r, 0);
				store_char_in_data(r, esc >> 16);
			} else {
				store_char_in_data(r, esc);
			}
			break;
		default:
			store_char_in_data(r, (*re)[-1]);
			break;
		}

	r->err_str = L"No closing ']' bracket";
}

static void
relocate(struct wslre *r, int begin, int shift)
{
	emit(r, END);
	memmove(r->code + begin + shift, r->code + begin, (r->code_size - begin) * sizeof(r->code[0]));
	r->code_size += shift;
}

static void
quantifier(struct wslre *r, int prev, int op)
{
	if (r->code[prev] == EXACT && r->code[prev + 2] > 1) {
		r->code[prev + 2]--;
		emit(r, EXACT);
		emit(r, r->code[prev + 1] + r->code[prev + 2]);
		emit(r, 1);
		prev = r->code_size - 3;
	}
	relocate(r, prev, 2);
	r->code[prev] = op;
	set_jump_offset(r, prev + 1, prev);
}

static void
exact_one_char(struct wslre *r, int ch)
{
	emit(r, EXACT);
	emit(r, r->data_size);
	emit(r, 1);
	store_char_in_data(r, ch);
}

static void
fixup_branch(struct wslre *r, int fixup)
{
	if (fixup > 0) {
		emit(r, END);
		set_jump_offset(r, fixup, fixup - 2);
	}
}

static void
compile(struct wslre *r, const wchar_t **re)
{
	int	op, esc, branch_start, last_op, fixup, cap_no, level;

	fixup = 0;
	level = r->num_caps;
	branch_start = last_op = r->code_size;

	for (;;)
		switch (*(*re)++) {
		case '\0':
			(*re)--;
			return;
			/* NOTREACHED */
			break;
		case '^':
			emit(r, BOL);
			break;
		case '$':
			emit(r, EOL);
			break;
		case '.':
			last_op = r->code_size;
			emit(r, ANY);
			break;
		case '[':
			last_op = r->code_size;
			anyof(r, re);
			break;
		case '\\':
			last_op = r->code_size;
			esc = get_escape_char(re);
			if (esc & 0xff0000) {
				emit(r, esc >> 16);
			} else {
				exact_one_char(r, esc);
			}
			break;
		case '(':
			last_op = r->code_size;
			cap_no = ++r->num_caps;
			emit(r, OPEN);
			emit(r, cap_no);

			compile(r, re);
			if (*(*re)++ != ')') {
				r->err_str = L"No closing bracket";
				return;
			}

			emit(r, CLOSE);
			emit(r, cap_no);
			break;
		case ')':
			(*re)--;
			fixup_branch(r, fixup);
			if (level == 0) {
				r->err_str = L"Unbalanced brackets";
				return;
			}
			return;
			/* NOTREACHED */
			break;
		case '+':
		case '*':
			op = (*re)[-1] == '*' ? STAR: PLUS;
			if (**re == '?') {
				(*re)++;
				op = op == STAR ? STARQ : PLUSQ;
			}
			quantifier(r, last_op, op);
			break;
		case '?':
			quantifier(r, last_op, QUEST);
			break;
		case '|':
			fixup_branch(r, fixup);
			relocate(r, branch_start, 3);
			r->code[branch_start] = BRANCH;
			set_jump_offset(r, branch_start + 1, branch_start);
			fixup = branch_start + 2;
			r->code[fixup] = 0xff;
			break;
		default:
			(*re)--;
			last_op = r->code_size;
			exact(r, re);
			break;
		}
}

int
wslre_compile(struct wslre *r, const wchar_t *re)
{
	r->err_str = NULL;
	r->code_size = r->data_size = r->num_caps = r->anchored = 0;

	if (*re == '^')
		r->anchored++;

	emit(r, OPEN);	/* This will capture what matches full RE */
	emit(r, 0);

	while (*re != '\0')
		compile(r, &re);

	if (r->code[2] == BRANCH)
		fixup_branch(r, 4);

	emit(r, CLOSE);
	emit(r, 0);
	emit(r, END);

	return (r->err_str == NULL ? 1 : 0);
}

static int match(const struct wslre *, int,
		const wchar_t *, int, int *, struct wcap *);

static void
loop_greedy(const struct wslre *r, int pc, const wchar_t *s, int len, int *ofs)
{
	int	saved_offset, matched_offset;

	saved_offset = matched_offset = *ofs;

	while (match(r, pc + 2, s, len, ofs, NULL)) {
		saved_offset = *ofs;
		if (match(r, pc + r->code[pc + 1], s, len, ofs, NULL))
			matched_offset = saved_offset;
		*ofs = saved_offset;
	}

	*ofs = matched_offset;
}

static void
loop_non_greedy(const struct wslre *r, int pc, const wchar_t *s,int len, int *ofs)
{
	int	saved_offset = *ofs;

	while (match(r, pc + 2, s, len, ofs, NULL)) {
		saved_offset = *ofs;
		if (match(r, pc + r->code[pc + 1], s, len, ofs, NULL))
			break;
	}

	*ofs = saved_offset;
}

static int
is_any_of(const wchar_t *p, int len, const wchar_t *s, int *ofs)
{
	int	i, ch;

	ch = s[*ofs];

	for (i = 0; i < len; i++)
		if (p[i] == ch) {
			(*ofs)++;
			return (1);
		}

	return (0);
}

static int
is_any_but(const wchar_t *p, int len, const wchar_t *s, int *ofs)
{
	int	i, ch;

	ch = s[*ofs];

	for (i = 0; i < len; i++)
		if (p[i] == ch)
			return (0);

	(*ofs)++;
	return (1);
}

static int
match(const struct wslre *r, int pc, const wchar_t *s, int len,
		int *ofs, struct wcap *caps)
{
	int	n, saved_offset, res = 1;

	while (res && r->code[pc] != END) {

		assert(pc < r->code_size);
		assert(pc < (int) (sizeof(r->code) / sizeof(r->code[0])));

		switch (r->code[pc]) {
		case BRANCH:
			saved_offset = *ofs;
			res = match(r, pc + 3, s, len, ofs, caps);
			if (res == 0) {
				*ofs = saved_offset;
				res = match(r, pc + r->code[pc + 1],
				    s, len, ofs, caps);
			}
			pc += r->code[pc + 2]; 
			break;
		case EXACT:
			res = 0;
			n = r->code[pc + 2];	/* String length */
			if (n <= len - *ofs && !memcmp(s + *ofs, r->data +
			    r->code[pc + 1], n*sizeof(r->data[0]))) {
				(*ofs) += n;
				res = 1;
			}
			pc += 3;
			break;
		case QUEST:
			res = 1;
			saved_offset = *ofs;
			if (!match(r, pc + 2, s, len, ofs, caps))
				*ofs = saved_offset;
			pc += r->code[pc + 1];
			break;
		case STAR:
			res = 1;
			loop_greedy(r, pc, s, len, ofs);
			pc += r->code[pc + 1];
			break;
		case STARQ:
			res = 1;
			loop_non_greedy(r, pc, s, len, ofs);
			pc += r->code[pc + 1];
			break;
		case PLUS:
			if ((res = match(r, pc + 2, s, len, ofs, caps)) == 0)
				break;

			loop_greedy(r, pc, s, len, ofs);
			pc += r->code[pc + 1];
			break;
		case PLUSQ:
			if ((res = match(r, pc + 2, s, len, ofs, caps)) == 0)
				break;

			loop_non_greedy(r, pc, s, len, ofs);
			pc += r->code[pc + 1];
			break;
		case SPACE:
			res = 0;
			if (*ofs < len && isspace(((wchar_t *)s)[*ofs])) {
				(*ofs)++;
				res = 1;
			}
			pc++;
			break;
		case NONSPACE:
			res = 0;
			if (*ofs <len && !isspace(((wchar_t *)s)[*ofs])) {
				(*ofs)++;
				res = 1;
			}
			pc++;
			break;
		case DIGIT:
			res = 0;
			if (*ofs < len && isdigit(((wchar_t *)s)[*ofs])) {
				(*ofs)++;
				res = 1;
			}
			pc++;
			break;
		case ANY:
			res = 0;
			if (*ofs < len) {
				(*ofs)++;
				res = 1;
			}
			pc++;
			break;
		case ANYOF:
			res = 0;
			if (*ofs < len)
				res = is_any_of(r->data + r->code[pc + 1],
					r->code[pc + 2], s, ofs);
			pc += 3;
			break;
		case ANYBUT:
			res = 0;
			if (*ofs < len)
				res = is_any_but(r->data + r->code[pc + 1],
					r->code[pc + 2], s, ofs);
			pc += 3;
			break;
		case BOL:
			res = *ofs == 0 ? 1 : 0;
			pc++;
			break;
		case EOL:
			res = *ofs == len ? 1 : 0;
			pc++;
			break;
		case OPEN:
			if (caps != NULL)
				caps[r->code[pc + 1]].ptr = s + *ofs;
			pc += 2;
			break;
		case CLOSE:
			if (caps != NULL)
				caps[r->code[pc + 1]].len = (s + *ofs) -
				    caps[r->code[pc + 1]].ptr;
			pc += 2;
			break;
		case END:
			pc++;
			break;
		default:
			printf("unknown cmd (%d) at %d\n", r->code[pc], pc);
			assert(0);
			break;
		}
	}

	return (res);
}

int
wslre_match(const struct wslre *r, const wchar_t *buf, int len,
		struct wcap *caps)
{
	int	i, ofs = 0, res = 0;

	if (r->anchored) {
		res = match(r, 0, buf, len, &ofs, caps);
	} else {
		for (i = 0; i < len && res == 0; i++) {
			ofs = i;
			res = match(r, 0, buf, len, &ofs, caps);
		}
	}

	return (res);
}
