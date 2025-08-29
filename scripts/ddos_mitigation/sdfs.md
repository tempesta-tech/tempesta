# QA 

##  Junior
* Q: Какие типы тестирования есть и в чем они заключаются
  - Q(eng): What types of testing exist and what do they involve? 
  - A: функциональное, системное, интеграционное, регрессионное, приемочное, инсталляционное
* Q: Что лучше тестировать в функциональных тестах а что в юнит
  - Q(eng): What should be tested with functional tests vs. unit tests? 
  - A: юнит тесты для тестирования функций или других мелких частей приложение. Функциональные - тестирование поведения приложеняи
* Q: Можно ли тестированием гарантировать отсутсвие ошибок?
  - Q(eng): Can testing guarantee the complete absence of bugs?
  - A: No

## Middle
* Q: Какими утилитами code coverage приходилось пользоваться?
  - Q(eng) Which code coverage tools have you worked with?
  - A: Python(coverage, pytest-cov, nose2 + coverage), C/C++ (gcov, lcov, llvm-cov)
* Q: Как составляете тестовый план? Пошагово опишите подход к созданию тестов для нового приложения реализовавшего HTTP/2 протокол?
  - Q(eng): How do you create a test plan? Describe step by step your approach to designing tests for a new application that implements the HTTP/2 protocol.
  - A: Не должно быть пальцем в небо. RFC, reading code

## Senior  
* Q: Что такое Black Box, White Box
  - Q(eng): What is the Black Box and White Box
  - A: Черный ящик - неизестная внутренность приложения. Тестируется по принципу передал данные - получил результат (io). White-Box - известно внутреннее строение, алгоритмы. Детальная проверка внутренностей
* Q: Как протестировать систему, которая должна работать годами без перезапуска?
  - Q(eng): How would you test a system that is supposed to run for years without a restart?
  - A: long-run тесты, стресс тесты (утечки памяти, не закрытые дескрипторы), fault injection

# Backend: 
## Junior
* Q: Как хранить сессию пользователя?
  - Q(eng): How to store a user session?
  - A: cookies, access token, jwt token in local storage
* Q: Для чего заголовок Access-Control-Allow-Origin и причем тут Cross-Origin Resource Sharing (CORS)
  - Q(eng): What is the purpose of the Access-Control-Allow-Origin header, and how is it related to Cross-Origin Resource Sharing (CORS)?
  - A: резрешения на получение доступа к ресурсам домена отличном от оригинального (например с domain.com делаем запрос на site.net). CORS - механизм управления резрешениями
* Q: Каким образом обычно передают файл с фронта на бек
  - Q(eng): How is a file usually transferred from the frontend to the backend?
  - A: Запросом с content-type = multipart/form-data. Еще иногда делают base64 файла и отправляют строкой в json обьекте

## Middle
* Q: Если запросы долго выполняются в бд, как мы можем понять в чем причина?
  - Q(eng): If database queries take too long, how can we find the reason?
  - A:show processlist; explain; slow query log;
* Q: Таблица имеет только одну строковую колонку. Как мне вывести все строки, имеющие дубликаты с числом дубликатов? 
  - Q(eng): A table has only one string column. How can you output all rows that have duplicates, along with the number of duplicates?
  - A: group by для аггрегации и having для фильтрации

## Senior
* Q: Как сделать вложенные комментарии в блоге и как их отображать?
  - Q(eng): How would you implement nested comments in a blog and how would you select them from the db?
  - A: в тиблице комментариев надо добавить поле parent_id как ссылка на эту же таблицу. Получить комменты можно через Recursive CTE
* Q: Что такое горизонтальное и вертикальное масштабирование и в чем разница
  - Q(eng): What is horizontal and vertical scaling, and what is the difference?
  - A: Горизонтальное - добавление дополнительных серверов, вертикальное - обновление оборудования сервера на более производитьное. 

# DevOps
## Junior
* Q: Какие есть методы контейнеризации?
  - Q(eng): What containerization methods are there?
  - A: docker, containerd + runc, podman, lxc/lxd, system-nspawn, bsd jail etc
* Q: Какой процесс сборки Debian пакетов, какие файлы для этого используются и какую роль они играют?
  - Q(eng): What is the process of building Debian packages, which files are used for this, and what role do they play?
  - A: control, rules, changelog, compat
* Q: Какими утилитами можно проверить открытые порты ?
  - Q(eng): Which tools can be used to check open ports?
  - A: netstat, lsof, nmap, nc, telnet
## Middle
* Q: Как происходит blue-green и канареечнаях схема деплоя
  - Q(eng): How do blue-green and canary deployment strategies work?
  - A: blue-green есть 2 среды: одна старая, вторая новая, когда зарелизили новую и проверили что все ок, происходит переключение из старой на новую.
       В канареечном типе тоже есть 2 варианта, но он доступен ограничегому кол-ву пользователей. Если для ограниченого кол-во нету проблем, тогда 
       процент пользователей повышают до 10%, потом до 50% и потом все 100%.
* Q: Что такое CGroups и как он используется
  - Q(eng): What are CGroups and how are they used?
  - A: механиз ядра линукс позволяющий ограничивать ресурсы. Испльзуется в контейнеризации, системных ресурсах (через systemd), нагрузочном тестировании
  - 
## Senior
* Q: Что такое NAT и для чего он нужен
  - Q(eng): What is NAT and what is it used for?
  - A: технология замены ip адресов на границе сети. Меняет IP-адреса в пакетах проходящие через маршрутизотор или шлюз. 
       Заменяет внутренний IP на внешний. Упрощаяет схему выхода в интернет, за одним публичным IP могут быть тысячи внутренних
* Q: Каким образом можно обновить настройки BIOS или EUFI на удаленной машине
  - Q(eng): How can BIOS or UEFI settings be updated on a remote machine?
  - A: KVM-over-IP, IPMI, iDRAC,iLO. Как отдельное устройство или контроллер на сервере

# Network:
## Junior
* Q: Разница между tcp и udp? 
  - Q(eng): What is the difference between TCP and UDP?
  - A: tcp гарантирует доставку данных и их порядок, нету потерь, медленный относительно udp
* Q: Какие запросы неидемпотентные?
  - Q(eng): Which requests are non-idempotent?
  - A: POST, PATCH. Меняют данные и возвращают разные результаты при повторном вызове
* Q: Как HTTP позволяет управляет кэшированием?
  - Q(eng): How does HTTP allow controlling caching?
  - A: Cache-Control, Age, Data, Last-Modified, Expires

## Middle
* Q: Разница между HTTP1 и HTTP2
  - Q(eng): The difference between HTTP/1 and HTTP/2
  - A: http2 бинарный, мультиплексирование позволяет в tcp-соединение слать несколько запросов через собственные потоки, 
      сжатие заголовков через hpack, приоритеты потоков (грузить css сначала вместо чего-то другого)
* Q: Что такое http pipelining ?
  - Q(eng): What is HTTP pipelining?
  - A: возможность отправить несколько запросов в подряд не дожидаясь ответов. Сервер отвечает пачкой в том порядке, в котором пришли запросы
## Senior
* Q: Что такое сетевая модель OSI, сколько уровней и какие? 
  - Q(eng): What is the OSI network model, how many layers does it have, and which ones?
  - A: Open Systems Interconnection. Набор сетевых протоколов разного уровня для сетевого взаимодействия. 7 уровней (физический, канальный, сетевой, транспортный, сеансовый, представительский, прикладной)
 
# Python:
## Junior
* Q: В чем разница между переменными класса и экземпляра класса
  - Q(eng): What is the difference between class variables and instance variables?
  - A: Переменные класса (static variables) доступны всем обьектам, изменяя переменную в одном обьекте, она изменится и
        в другом. Переменные экземпляра класса индивидуальные для каждого из них
* Q: Что такое списки и что общего между словарем и множеством? 
  - Q(eng): What are lists, and what do a dictionary and a set have in common? 
  - A: список - структура хранящая набор элементов связанных между собой ссылками, элементы в памяти находятся не рядом, а 
        могут быть где угодно, в питоне память под списки выделяется пачками как оптимизация, больше похоже на динамические массивы. 
        Словари и множества внутри устроены через хэш таблицы.
* Q: Что такое декоратор и для чего он?
  - Q(eng): What is a decorator and what is it used for?
  - A: Паттерт программирование, в питоне есть синтаксических сахар. Расширяет функцию или класс без изменения внутреннего алгоритма работы
- Q: Что такое контекстный менеджер и для чего он нужен?
  - Q(eng): What is a context manager and what is it used for?
  - A: Обьект, который помогает управлять ресурсами, обеспечивает их правильное открытие и закрытие даже в случае ошибки

## Middle
* Q: Что такое итераторы и генераторы и для чего нужны? 
  - Q(eng): What are iterators and generators, and what are they used for?
  - A: Итератор - паттерт программирования, интерфейс описывающий последовательный доступ к элементам коллекции не раскрывая внутреннюю реализацию. 
       Генератор - частный случай итератора, есть в питоне сахар через yield. Используются для оптимизации обработки больших обьемов данных, так как
       позволяют обрабатывать элементы по одному генерируя их на лету, а не хранить весь набор данных сразу в памяти.
* Q: В каких случаях лучше использовать асинхронное программирование, а в каких потоки или процессы. Например, при обработке
    картинок или парсинга данных из интернет ресурсов.
  - Q(eng): In which cases is it better to use asynchronous programming, and in which cases threads or processes? 
       For example, when processing images or parsing data from internet resources.
  - A: Асинхронное для IO-bound задач (интернет, диск и тд), потоки или процессы для CPU-bound задач (обработка текств, картинок и тд)

## Senior
* Q: Что такое GIL и для чего нужен. Потоки и процессы в питоне
  - Q(eng): What is the GIL and why is it needed? Explain threads and processes in Python.
  - A: Global Interpeterer Lock - блокирует параллельное выполнение потоков и заставляет их работать по-очередно. 
      В случае, если потоки выполняют IO-операции, GIL блокировка для них снимается. Параллельно делать запросы можно. 
      Для ускорение обработки CPU-bound лучше использовать Multiprocessing. В последних версиях питона можно отключать GIL
* Q: Что такое функция type ? Какие есть альтернативы? 
  - Q(eng): What is the type function? What alternatives are there?
  - A: работает в 2х режимах. С один параметром возвращает тип данных. Если передать 3 параметра - сгенерирует класс.
     Первый параметр - название нового класса, потом кортеж из классов который надо наследовать, и третий - словарь методов и атрибутов.
     Создание классов - метапрограммирование, также можно сделать через классы переопределив `__new__` метод
