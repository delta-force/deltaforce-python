#define PY_SSIZE_T_CLEAN

#include "Python.h"
#include <ctype.h>
#include <stddef.h>

PyTaintObject *
PyTaint_EmptyMerits()
{
    /** Generate a dict to hold the merits and the sources. */
    
    PyObject *taint = PyDict_New();
    
    PyObject *merits = PyTuple_New(0);
    PyObject *sources = PySet_New(NULL);
    
    PyDict_SetItemString(taint, "merits", merits);
    PyDict_SetItemString(taint, "sources", sources);
    
    return (PyTaintObject*)taint;
}

PyTaintObject *
_PyTaint_AddMerit(PyTaintObject *taint, PyObject *merit)
{
    PyObject *result;
    PyObject *rmerit;
    PyObject *rsource;
    
    Py_ssize_t n, i;
    PyObject *item;
    PyObject *ms;
    PyObject *ss;
    
    result = PyDict_New();
    
    if(result == NULL)
        return NULL;
    
    ms = PyDict_GetItemString((PyObject*)taint, "merits");
    ss = PyDict_GetItemString((PyObject*)taint, "sources");
    
    n = PyTuple_GET_SIZE(ms);
    rmerit = PyTuple_New(n + 1);
    if (rmerit == NULL)
        return NULL;

    for (i = 0; i < n; i++) {
        item = PyTuple_GET_ITEM(ms, i);
        Py_INCREF(item);
        PyTuple_SET_ITEM(rmerit, i, item);
    }
    Py_INCREF(merit);
    PyTuple_SET_ITEM(rmerit, n, merit);
    
    /** Just copy the sources. */
    rsource = PySet_New(ss);
    
    PyDict_SetItemString(result, "merits", rmerit);
    PyDict_SetItemString(result, "sources", rsource);

    return (PyTaintObject*)result;
}

int
_PyTaint_TaintStringListItems(PyObject *target, PyTaintObject *source) {
    if (PyTaint_IS_CLEAN(source))
        return 1;
    Py_ssize_t i, n;
    PyObject *item, *old_item;
    n = PyList_GET_SIZE(target);

    for (i = 0; i < n; i++) {
        item = PyList_GET_ITEM(target, i);
        if (PyString_CHECK_INTERNED(item) ||
            item->ob_refcnt > 1) {
            old_item = item;
            item = PyString_FromStringAndSizeSameMerits(
                                      PyString_AS_STRING(item),
                                      PyString_GET_SIZE(item),
                                      source);
            if (item == NULL)
                return -1;
            Py_DECREF(old_item);
            PyList_SET_ITEM(target, i, item);
        } else {
            PyString_ASSIGN_MERITS(item, source);
        }
    }
    return 1;
}

PyObject*
_PyTaint_TaintStringTupleItems(PyObject *target, PyTaintObject *source) {
    Py_ssize_t i, n;
    PyObject *item, *old_item, *result;
    n = PyTuple_GET_SIZE(target);

    if (PyTaint_IS_CLEAN(source))
        return target; // We assume that target is not tainted.

    if (target->ob_refcnt == 1) {
        result = target; // Taint in place
    } else {
        result = PyTuple_New(n);
        if (result == NULL) {
            goto done;
        }
    }

    for (i = 0; i < n; i++) {
        item = PyTuple_GET_ITEM(target, i);
        if (PyString_CHECK_INTERNED(item) ||
            item->ob_refcnt > 1) {
            old_item = item;
            item = PyString_FromStringAndSizeSameMerits(
                                      PyString_AS_STRING(item),
                                      PyString_GET_SIZE(item),
                                      source);
            if (item == NULL) {
                result = NULL;
                goto done;
            }
            if (target == result)
                Py_DECREF(old_item);
            PyTuple_SET_ITEM(result, i, item);
        } else {
            PyString_ASSIGN_MERITS(item, source);
        }
    }

  done:
    // steal reference
    if (target != result)
        Py_DECREF(target);

    return result;
}

PyObject*
_PyTaint_TaintUnicodeTupleItems(PyObject *target, PyTaintObject *source) {
    Py_ssize_t i, n;
    PyObject *item, *old_item, *result;
    n = PyTuple_GET_SIZE(target);

    if (PyTaint_IS_CLEAN(source))
        return target; // We assume that target is not tainted.

    if (target->ob_refcnt == 1) {
        result = target; // Taint in place
    } else {
        result = PyTuple_New(n);
        if (result == NULL) {
            goto done;
        }
    }

    for (i = 0; i < n; i++) {
        item = PyTuple_GET_ITEM(target, i);
        if (item->ob_refcnt > 1 ||
            PyUnicode_IsShared((PyUnicodeObject*)item)) {
            old_item = item;
            item = PyUnicode_FromUnicodeSameMerits(
                                      PyUnicode_AS_UNICODE(item),
                                      PyUnicode_GET_SIZE(item),
                                      source);
            if (item == NULL) {
                result = NULL;
                goto done;
            }
            if (target == result)
                Py_DECREF(old_item);
            PyTuple_SET_ITEM(result, i, item);
        } else {
            PyUnicode_ASSIGN_MERITS(item, source);
        }
    }

  done:
    // steal reference
    if (target != result)
        Py_DECREF(target);

    return result;
}


PyObject*
PyTaint_AssignToObject(PyObject *obj, PyTaintObject* taint) {
    if (PyString_Check(obj))
        return PyString_AssignTaint((PyStringObject*)obj, taint);
    if (PyUnicode_Check(obj))
        return PyUnicode_AssignTaint((PyUnicodeObject*)obj, taint);

    PyErr_Format(PyExc_TypeError,
                "Attempting tainting of non-taintable object of type %.200s",
                Py_TYPE(obj)->tp_name);
    return NULL;
}

int
PyTaint_IsTaintable(PyObject *obj) {
    return PyString_Check(obj) || PyUnicode_Check(obj);
}

int
_PyTaint_TaintUnicodeListItems(PyObject *target, PyTaintObject *source) {
    if (PyTaint_IS_CLEAN(source))
        return 1;
    Py_ssize_t i, n;
    PyObject *item, *old_item;
    n = PyList_GET_SIZE(target);

    for (i = 0; i < n; i++) {
        item = PyList_GET_ITEM(target, i);
        if (PyUnicode_IsShared((PyUnicodeObject*)item) ||
            item->ob_refcnt > 1) {
            old_item = item;
            item = PyUnicode_FromUnicodeSameMerits(
                                      PyUnicode_AS_UNICODE(item),
                                      PyUnicode_GET_SIZE(item),
                                      source);
            if (item == NULL)
                return -1;
            Py_DECREF(old_item);
            PyList_SET_ITEM(target, i, item);
        } else {
            PyUnicode_ASSIGN_MERITS(item, source);
        }
    }
    return 1;
}

int
PyTaint_PropagateTo(PyTaintObject **target,
                    PyTaintObject *source) {
    PyTaintObject *result = NULL;
    if (PyTaint_PropagationResult(&result, *target, source) == -1)
        return -1;
    Py_XDECREF(*target);
    *target = result;
    return 1;
}

PyTaintObject*
_PyTaint_GetFromObject(PyObject *obj) {
    if (PyString_Check(obj)) {
        Py_XINCREF(PyString_GET_MERITS(obj));
        return PyString_GET_MERITS(obj);
    }
    if (PyUnicode_Check(obj)) {
        Py_XINCREF(PyUnicode_GET_MERITS(obj));
        return PyUnicode_GET_MERITS(obj);
    }
    Py_FatalError("Attempting to obtain taint from non-taintable object.");
    // the line below is to surpress compiler warning
    return NULL;
}

int
PyTaint_PropagationResult(PyTaintObject **target,
                          PyTaintObject *ta,
                          PyTaintObject *tb)
{
    PyObject *new_taint = NULL;
    PyObject *new_merits = NULL;
    PyObject *new_src = NULL;
    
    register PyObject *src, *m;
    PyObject *src_merits;
    PyObject *src_sources;
    
    // n is upper bound of new_merits size, j is its actual size at given
    // moment
    register Py_ssize_t i, n, j;
    int contains;

    PyObject *a, *b;
    PyObject *as, *bs;
    

    // Both untainted
    if (PyTaint_IS_CLEAN(ta) && PyTaint_IS_CLEAN(tb)) {
        goto done;
    }
    
    j = 0;

    // Both tainted - intersect two merits list
    if (!PyTaint_IS_CLEAN(ta) && !PyTaint_IS_CLEAN(tb)) {
        a = PyDict_GetItemString((PyObject*)ta, "merits");
        b = PyDict_GetItemString((PyObject*)ta, "merits");
        
        n = PyTuple_GET_SIZE(a) > PyTuple_GET_SIZE(b) ?
              PyTuple_GET_SIZE(a) : PyTuple_GET_SIZE(b);
        new_merits = PyTuple_New(n);
        if (new_merits == NULL)
          return -1;

        for (i = 0; i < PyTuple_GET_SIZE(a); i++) {
            m = PyTuple_GET_ITEM(a, i);
            contains = PySequence_Contains((PyObject*)b, m);
            if (contains == -1)
                goto onError;
            if (contains == 1) {
                if (PyMerit_FULL_PROPAGATION(m) || \
                    PyMerit_PARTIAL_PROPAGATION(m)) {
                    Py_INCREF(m);
                    PyTuple_SET_ITEM(new_merits, j, m);
                    j += 1;
                } else if(!PyMerit_NONE_PROPAGATION(m)) {
                    PyErr_SetString(PyExc_ValueError,
                                    "Invalid taint propagation strategy.");
                    goto onError;
                }
            }
        }
        // _PyTupleResize will set new_merits to NULL on failure, so instead of
        // goto onError just return -1
        if (_PyTuple_Resize(&new_merits, j) != 0)
          return -1;
        
        /** Merge the sources */
        PyObject *merged = PyString_FromString("union");
        
        as = PyDict_GetItemString((PyObject*)ta, "sources");
        bs = PyDict_GetItemString((PyObject*)tb, "sources");
        
        new_src = PyObject_CallMethodObjArgs(as, merged, bs, NULL);
        
        if(new_src == NULL)
            goto onError;
            
        new_taint = PyDict_New();
        
        if(new_taint == NULL)
            goto onError;
        
        PyDict_SetItemString(new_taint, "sources", new_src);
        PyDict_SetItemString(new_taint, "merits", new_merits);
        
        goto done;
    }
    // One untainted, other tainted
    if (!PyTaint_IS_CLEAN(ta)) {
        src = (PyObject*)ta;
    } else { // ie. !PyTaint_IS_CLEAN(tb) is true
        src = (PyObject*)tb;
    }
    
    
    src_merits = PyDict_GetItemString(src, "merits");
    src_sources = PyDict_GetItemString(src, "sources");
    
    if(src_merits == NULL || src_sources == NULL)
        goto onError;
        
    new_taint = PyDict_New();
    
    PyDict_SetItemString(new_taint, "sources", src_sources);
    
    n = PyTuple_GET_SIZE(src_merits);
    new_merits = PyTuple_New(n);
    if (new_merits == NULL)
      return -1;

    for (i = 0; i < PyTuple_GET_SIZE(src_merits); i++) {
        m = PyTuple_GET_ITEM(src_merits, i);
        if (PyMerit_FULL_PROPAGATION(m)) {
            Py_INCREF(m);
            PyTuple_SET_ITEM(new_merits, j, m);
            j += 1;
        } else if (!PyMerit_NONE_PROPAGATION(m) && \
                   !PyMerit_PARTIAL_PROPAGATION(m)) {
            PyErr_SetString(PyExc_ValueError,
                            "Invalid taint propagation strategy.");
        }
    }

    // _PyTupleResize will set new_merits to NULL on failure, so instead of
    // goto onError just return
    if (_PyTuple_Resize(&new_merits, j) != 0)
      return -1;

    PyDict_SetItemString(new_taint, "merits", new_merits);

    done:
      Py_XDECREF(*target);
      *target = (PyTaintObject*)new_taint;
      return 1;

    onError:
      Py_DECREF(new_merits);
      Py_DECREF(new_src);
      
      return -1;
}

int
_PyTaint_ValidMerit(PyObject *merit) {
    if (!PyObject_HasAttrString(merit, "propagation")) {
        PyErr_SetString(PyExc_TypeError,
                        "Invalid merit object passed.");
        return -1;
    }

    if (!(PyMerit_FULL_PROPAGATION(merit) || \
          PyMerit_NONE_PROPAGATION(merit) || \
          PyMerit_PARTIAL_PROPAGATION(merit))) {
        PyErr_SetString(PyExc_TypeError,
                        "Merit object has invalid propagation strategy.");
        return -1;
    }
    return 1;
}
