--Tablica ze wszystkimi wpisami
drop table if exists entries;
create table entries (
  id integer primary key autoincrement,
  username text not null,
  title text not null,
  text text not null
);

--Tablica z danymi wszystkich u¿ytkowników
drop table if exists users;
create table users (
  user_id integer primary key autoincrement,
  username text not null,
  email text not null,
  password text not null,
  salt text not null
);
--Tablica do banów - zapisuje nieudane logowania z danego ip i czas ostatniej próby logowania. S³u¿y do dawania banów, odliczania czasu do koñca bana i blokowania zbyt czêstych prób logowañ
drop table if exists logs;
create table logs(
	ip text primary key,
	addcount integer default 0,
	bantime integer default 0,
	pause integer default 0

);

--Tablica otwartych sesji - przy logowaniu wrzucamy tu usera i jego ip, przy wylogowaniu - kasujemy. Jesli ktoœ chce siê zalogowaæ na usera który ju¿ tu jest, na konto wysy³any jest mail o podejrzanym zachowaniu konta.
drop table if exists sessions;
create table sessions(
	ip text not null,
	username text not null
);