package siv

import (
    "crypto/cipher"
    "crypto/subtle"
    "errors"
    "hash"

    "github.com/pedroalbanese/cmac"
    "github.com/pedroalbanese/pmac"
)

// MaxAssociatedDataItems é o número máximo de itens de dados associados
const MaxAssociatedDataItems = 126

var (
    // ErrNotAuthentic indica que o texto cifrado está malformado ou corrompido
    ErrNotAuthentic = errors.New("siv: authentication failed")

    // ErrTooManyAssociatedDataItems indica que mais do que MaxAssociatedDataItems foram fornecidos
    ErrTooManyAssociatedDataItems = errors.New("siv: too many associated data items")
)

// Cipher é uma instância de AES-SIV, configurada com CMAC ou PMAC
type Cipher struct {
    h hash.Hash
    b cipher.Block
    tmp1, tmp2 pmac.Block
}

// NewCMACCipher retorna um novo cifrador SIV usando CMAC.
func NewCMACCipher(macBlock, ctrBlock cipher.Block) (c *Cipher, err error) {
    c = new(Cipher)
    h, err := cmac.New(macBlock)
    if err != nil {
        return nil, err
    }

    c.h = h
    c.b = ctrBlock

    // Use o tamanho do bloco diretamente
//    blockSize := macBlock.BlockSize()
    c.tmp1 = pmac.Block{}
    c.tmp2 = pmac.Block{}

    return c, nil
}

// NewPMACCipher retorna um novo cifrador SIV usando PMAC.
func NewPMACCipher(macBlock, ctrBlock cipher.Block) (c *Cipher, err error) {
    c = new(Cipher)
    h := pmac.New(macBlock)
    c.h = h
    c.b = ctrBlock

    // Use o tamanho do bloco diretamente
//    blockSize := macBlock.BlockSize()
    c.tmp1 = pmac.Block{}
    c.tmp2 = pmac.Block{}

    return c, nil
}

// Overhead retorna a diferença entre o comprimento do texto simples e do texto cifrado.
func (c *Cipher) Overhead() int {
    return c.h.Size()
}

// Seal criptografa e autentica o texto simples e os dados associados, e anexa o resultado a dst, retornando o slice atualizado.
func (c *Cipher) Seal(dst []byte, plaintext []byte, data ...[]byte) ([]byte, error) {
    if len(data) > MaxAssociatedDataItems {
        return nil, ErrTooManyAssociatedDataItems
    }

    // Autentica
    iv := c.s2v(data, plaintext)
    ret, out := sliceForAppend(dst, len(iv)+len(plaintext))
    copy(out, iv)

    // Criptografa
    zeroIVBits(iv)

    ctr := cipher.NewCTR(c.b, iv)
    ctr.XORKeyStream(out[len(iv):], plaintext)

    return ret, nil
}

// Open descriptografa o texto cifrado, autentica o texto simples descriptografado e os dados associados e, se bem-sucedido, anexa o texto resultante a dst, retornando o slice atualizado.
func (c *Cipher) Open(dst []byte, ciphertext []byte, data ...[]byte) ([]byte, error) {
    if len(data) > MaxAssociatedDataItems {
        return nil, ErrTooManyAssociatedDataItems
    }
    if len(ciphertext) < c.Overhead() {
        return nil, ErrNotAuthentic
    }

    // Descriptografa
    iv := c.tmp1[:c.Overhead()]
    copy(iv, ciphertext)
    zeroIVBits(iv)

    ctr := cipher.NewCTR(c.b, iv)

    ret, out := sliceForAppend(dst, len(ciphertext)-len(iv))
    ctr.XORKeyStream(out, ciphertext[len(iv):])

    // Autentica
    expected := c.s2v(data, out)
    if subtle.ConstantTimeCompare(ciphertext[:len(iv)], expected) != 1 {
        return nil, ErrNotAuthentic
    }

    return ret, nil
}

func (c *Cipher) s2v(s [][]byte, sn []byte) []byte {
    h := c.h
    h.Reset()

    tmp, d := c.tmp1, c.tmp2
    tmp.Clear()

    _, err := h.Write(tmp[:])
    if err != nil {
        panic(err)
    }

    copy(d[:], h.Sum(d[:0]))
    h.Reset()

    for _, v := range s {
        _, err := h.Write(v)
        if err != nil {
            panic(err)
        }

        copy(tmp[:], h.Sum(tmp[:0]))
        h.Reset()
        d.Dbl()

        xor(d[:], tmp[:])
    }

    tmp.Clear()

    if len(sn) >= h.BlockSize() {
        n := len(sn) - len(d[:])
        copy(tmp[:], sn[n:])
        _, err = h.Write(sn[:n])
        if err != nil {
            panic(err)
        }
    } else {
        copy(tmp[:], sn)
        tmp[len(sn)] = 0x80
        d.Dbl()
    }

    xor(tmp[:], d[:])

    _, err = h.Write(tmp[:])
    if err != nil {
        panic(err)
    }

    return h.Sum(tmp[:0])
}

func zeroIVBits(iv []byte) {
    // "We zero-out the top bit in each of the last two 32-bit words
    // of the IV before assigning it to Ctr"
    //  — http://web.cs.ucdavis.edu/~rogaway/papers/siv.pdf
    iv[len(iv)-8] &= 0x7f
    iv[len(iv)-4] &= 0x7f
}

// XOR o conteúdo de b em a no lugar
func xor(a, b []byte) {
    for i := range b {
        a[i] ^= b[i]
    }
}

// Função auxiliar para criar o slice final e o slice extra
func sliceForAppend(in []byte, n int) (head, tail []byte) {
    if total := len(in) + n; cap(in) >= total {
        head = in[:total]
    } else {
        head = make([]byte, total)
        copy(head, in)
    }

    tail = head[len(in):]
    return
}
