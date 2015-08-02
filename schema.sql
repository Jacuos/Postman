--Tablica ze wszystkimi wpisami
drop table if exists entries;
create table entries (
  id integer primary key autoincrement,
  username text not null,
  title text not null,
  text text not null
);

--Tablica z danymi wszystkich u�ytkownik�w
drop table if exists users;
create table users (
  user_id integer primary key autoincrement,
  username text not null,
  email text not null,
  password text not null,
  salt text not null
);
--Tablica do ban�w - zapisuje nieudane logowania z danego ip i czas ostatniej pr�by logowania. S�u�y do dawania ban�w, odliczania czasu do ko�ca bana i blokowania zbyt cz�stych pr�b logowa�
drop table if exists logs;
create table logs(
	ip text primary key,
	addcount integer default 0,
	bantime integer default 0,
	pause integer default 0

);

--Tablica otwartych sesji - przy logowaniu wrzucamy tu usera i jego ip, przy wylogowaniu - kasujemy. Jesli kto� chce si� zalogowa� na usera kt�ry ju� tu jest, na konto wysy�any jest mail o podejrzanym zachowaniu konta.
drop table if exists sessions;
create table sessions(
	ip text not null,
	username text not null
);