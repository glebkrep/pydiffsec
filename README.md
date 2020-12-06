# PyDiffSec - скрипт, для контроля изменений файловой системы
Написан с использованием Python 3.8.2
Работает и протестирован на macOS, Ubuntu


## Использование:

### 1)Вывести сообщение с описанием комманд:


```bash
python3 pydiffsec.py help
#или
python3 pydiffsec.py
```


### 2)Создать новый базовый файл (запись sha1 хэшей всех файлов в выбранной директории):

`[-d fileDir]` - указание директории для создания базового файла (по умолчанию - текущая директория/basefile/)

`[-hd hashDir]` - указание директории, которую нужно хэшировать (по умолчанию - текущая директория)
```bash
python3 pydiffsec.py new [-d fileDir] [-hd hashDir]
#все аргументы не обязательны
```


### 3)Cоздание нового отчета об изменений файлов:

`[-rd reportFileDir]` - указание директории для создания отчета (по умолчанию - текущая директория/basefile/)

`[-bd baseFileDir]` - указание директории, в которой находится базовый файл (по умолчанию - текущая директория/basefile/)

`[-r|-a pathInReport]` - выбор формата путей файлов в отчете (относительный|полный) (по умолчанию - полный)

`[-xml|-txt reportFormat]` - выбор формата отчета (по умолчанию - xml)

```bash
python3 pydiffsec.py report [-rd reportFileDir] [-bd baseFileDir] [-r|-a pathInReport] [-xml|-txt reportFormat] 
#все аргументы не обязательны
```
